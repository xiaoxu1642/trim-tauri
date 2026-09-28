// uninstall.js — 软件卸载（卸载域 MVP，竞品借鉴落地方案 P0，2026-09-28）
//
// 流程（方案 §4.3，2026-09-28 二轮拍板改静默优先）：列表（uninstall:list）→ 用户点卸载
// → 红色确认 → 后端静默优先链（白名单 msi/inno/nsis 先静默；不可静默或静默失败
// 自动回退原厂 UI，返回 usedSilent/fellBack 供前端如实提示）→ 卸载后复查
// 卸载键 → 残留扫描（uninstall:residue-scan，树形分组/置信度/默认勾选）→
// 受控清理（uninstall:residue-execute：文件回收站优先、注册表先备份后删）。
// 删除确认一律走 window.app.confirmDanger（位置参数，见 memoryclean 既有用法）。
(function () {
  'use strict';

  let inited = false;
  // 当前列表缓存：id -> 记录（卸载/残留扫描按 id 寻址）
  let apps = [];
  let currentScope = 'user';
  // 两个独立互斥标志（U-8 根因修复 2026-09-28：原先共用一个 running，卸载流程内
  // 调 loadApps() 被「running 即返回」的守卫静默吞掉——列表不刷新、残留面板停在
  // 长列表首屏之下，感知就是"卸载后没有残留扫描"）。
  let running = false;      // 卸载 / 残留清理互斥
  let enumerating = false;  // 列表枚举互斥
  // 最近一次残留扫描结果（渲染与勾选用）
  let findings = [];
  let currentAppId = '';
  // C2 孤儿扫描复用同一个面板：mode 决定「重新扫描」按钮回到哪条链，
  // 以及删除时传给后端的 appId（孤儿结果不属于任何单个程序，用合成 id 落批次报告）
  let residueMode = 'app';
  const ORPHAN_APP_ID = 'ORPHAN|machine';

  function esc(s) { return window.ds.esc(s); }
  function fmtSizeKb(kb) {
    kb = Number(kb) || 0;
    if (kb <= 0) return '—';
    const units = ['KB', 'MB', 'GB'];
    let v = kb, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
  }

  const KIND_LABEL = {
    reg_key: '注册表', folder: '目录', file: '文件', shortcut: '快捷方式',
  };
  const CONF_LABEL = { high: '高置信', medium: '中置信', low: '低置信（建议人工核对）' };

  // ==================== 应用图标（用户要求 2026-09-28：名称前显示真实图标） ====================
  // 复用 paths:file-icon / paths:app-icon（shellicon 提取）。两层缓存：
  // ① 内存 Map（会话内）② localStorage 落盘（跨会话，U-3；总量 1MB 上限，
  // 超限按 LRU 丢弃）。缓存键 = id|version：同 id 升级后版本变化自动失效。
  // 不放后端缓存的原因：paths 通道是通用面（路径绑定/残留扫描共用），
  // 在命令里注入按应用维度的缓存语义会污染其它调用方。
  const ICON_CACHE_KEY = 'uninstall-icon-cache-v1';
  const ICON_CACHE_MAX = 1 << 20;   // 落盘总量上限（dataURL 粗算与原图 1:1.37）
  const ICON_CACHE_ENTRY_MAX = 32 * 1024; // 单条超限不落盘（大图实时取）
  const ICON_CONCURRENCY = 4;       // 并发提取上限（shellicon 提取有进程外开销，4 路已打满）

  const iconCache = loadIconCache(); // key=id|version -> dataUrl | ''（失败也缓存，避免重扫重试）

  function loadIconCache() {
    try {
      const o = JSON.parse(localStorage.getItem(ICON_CACHE_KEY));
      if (o && typeof o === 'object' && !Array.isArray(o)) return new Map(Object.entries(o));
    } catch (_) { /* 损坏即重建 */ }
    return new Map();
  }

  // 持久化：超限丢最旧（Map 迭代序 = 插入序，命中即重插实现 LRU）；配额不足静默放弃
  function persistIconCache() {
    try {
      const out = {};
      let total = 0;
      const entries = [];
      for (const [k, v] of iconCache) {
        if (typeof v === 'string' && v.length && v.length <= ICON_CACHE_ENTRY_MAX) {
          entries.push([k, v]);
          total += v.length;
        }
      }
      while (entries.length && total > ICON_CACHE_MAX) {
        const [, v] = entries.shift();
        total -= v.length;
      }
      for (const [k, v] of entries) out[k] = v;
      localStorage.setItem(ICON_CACHE_KEY, JSON.stringify(out));
    } catch (_) { /* 配额不足不影响功能 */ }
  }

  const iconCacheKey = (a) => `${a.id}|${a.displayVersion || ''}`;

  // 图标源优先级：Appx Logo（.png 直接读图，U-3）→ displayIcon（剥 ,索引 后缀）→
  // 安装目录图标（app-icon 对目录取壳图标）。
  function iconSourcePaths(a) {
    const out = [];
    if (a.logoPath) out.push({ kind: 'png', path: a.logoPath });
    const di = String(a.displayIcon || '').split(',')[0].trim();
    if (di) out.push({ kind: 'file', path: di });
    if (a.installLocation) out.push({ kind: 'dir', path: a.installLocation });
    return out;
  }

  async function fetchIcon(app) {
    const key = iconCacheKey(app);
    if (iconCache.has(key)) {
      // LRU touch：命中即重插到 Map 尾部
      const v = iconCache.get(key);
      iconCache.delete(key);
      iconCache.set(key, v);
      return v;
    }
    let url = '';
    for (const src of iconSourcePaths(app)) {
      try {
        const resp = src.kind === 'png'
          ? await window.api.uninstall.appxLogo(src.path)
          : src.kind === 'file'
            ? await window.api.paths.fileIcon(src.path)
            : await window.api.paths.appIcon(src.path, null);
        if (resp && resp.success && resp.dataUrl) { url = resp.dataUrl; break; }
      } catch (e) { /* 图标失败不阻塞列表，占位兜底 */ }
    }
    iconCache.set(key, url);
    return url;
  }

  // 渲染完成后并发补图标（U-3：4 路并发池，shellicon/读图都是进程外或 IO 开销，
  // 串行 83 个约秒级 → 并发后亚秒；并发太高会打爆 shell 提取，不设更高）。
  // 用 dataset 定位单元格：渲染期间用户翻页/重扫时旧节点已 detached，直接跳过。
  async function hydrateIcons() {
    const pending = apps.filter((a) => {
      const cell = document.querySelector(`[data-un-icon="${CSS.escape(a.id)}"]`);
      return cell && cell.dataset.loaded !== '1';
    });
    let idx = 0;
    const worker = async () => {
      while (idx < pending.length) {
        const app = pending[idx++];
        const cell = document.querySelector(`[data-un-icon="${CSS.escape(app.id)}"]`);
        if (!cell || cell.dataset.loaded === '1') continue;
        const url = await fetchIcon(app);
        cell.dataset.loaded = '1';
        cell.innerHTML = url
          ? `<img src="${url}" alt="" draggable="false">`
          : '<span class="un-icon-fallback">▣</span>';
      }
    };
    await Promise.all(Array.from({ length: Math.min(ICON_CONCURRENCY, pending.length) }, worker));
    persistIconCache();
  }

  // ==================== 程序列表 ====================
  async function loadApps() {
    const listEl = document.getElementById('uninstallList');
    const countEl = document.getElementById('uninstallCount');
    if (enumerating) return;
    enumerating = true;
    // 自我安慰式进度：枚举期间进度条爬升封顶 99%，完成即 100% 收尾
    startFakeProgress(currentScope === 'windows' ? '正在枚举 Windows 应用…' : '正在枚举已安装程序…');
    listEl.innerHTML = '<div class="finder-empty">正在枚举…</div>';
    try {
      const resp = await window.api.uninstall.list(currentScope);
      if (!resp.success) throw new Error(resp.message || '枚举失败');
      apps = resp.data.apps || [];
      countEl.textContent = apps.length;
      if (!apps.length) {
        listEl.innerHTML = '<div class="finder-empty">没有枚举到已安装程序</div>';
        return;
      }
      listEl.innerHTML = currentScope === 'windows' ? renderWindowsApps() : renderWin32Apps();
      hydrateIcons();
    } catch (e) {
      listEl.innerHTML = `<div class="finder-empty">枚举失败：${esc(String(e.message || e))}</div>`;
      window.app?.toast?.('error', '枚举失败: ' + (e.message || e));
    } finally {
      finishFakeProgress();
      enumerating = false;
    }
  }

  // 用户应用（传统 Win32）：三个卸载注册表根合并，HiBit「程序名」83 项的口径
  function renderWin32Apps() {
    const rows = apps.map((a) => `
      <tr>
        <td><div class="finder-cell"><span class="un-icon" data-un-icon="${esc(a.id)}"></span><span class="finder-name-text">${esc(a.displayName)}</span></div></td>
        <td class="finder-col-size" style="width:180px"><span class="finder-name-text" style="opacity:.7">${esc(a.publisher || '—')}</span></td>
        <td class="finder-col-size" style="width:110px"><span class="finder-name-text" style="opacity:.7">${esc(a.displayVersion || '—')}</span></td>
        <td class="finder-col-size" style="width:90px">${fmtSizeKb(a.estimatedSizeKb)}</td>
        <td class="finder-col-size" style="width:110px"><span class="finder-name-text" style="opacity:.7" data-tip="注册表键最后写入时间，近似安装日期">${esc(a.installDate || '—')}</span></td>
        <td class="finder-col-size" style="width:150px">
          <button class="btn btn-secondary btn-small" data-un-app="${esc(a.id)}"${a.uninstallString ? '' : ' disabled data-tip="没有 UninstallString，无法调用原厂卸载器"'}>卸载</button>
        </td>
      </tr>`).join('');
    return `
      <table class="finder-table">
        <thead><tr><th>程序</th><th class="finder-col-size" style="width:180px">发行商</th><th class="finder-col-size" style="width:110px">版本</th><th class="finder-col-size" style="width:90px">大小</th><th class="finder-col-size" style="width:110px">安装日期</th><th class="finder-col-size" style="width:150px">操作</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  // Windows 应用（Appx）：按 HiBit 口径分「第三方应用 / Windows 应用」两组
  function renderWindowsApps() {
    const third = apps.filter((a) => a.group === 'third');
    const sys = apps.filter((a) => a.group !== 'third');
    const section = (title, list) => {
      if (!list.length) return '';
      const rows = list.map((a) => `
        <tr>
          <td><div class="finder-cell"><span class="un-icon" data-un-icon="${esc(a.id)}"></span><span class="finder-name-text">${esc(a.displayName)}</span></div></td>
          <td class="finder-col-size" style="width:190px"><span class="finder-name-text" style="opacity:.7">${esc(a.publisher || '—')}</span></td>
          <td class="finder-col-size" style="width:130px"><span class="finder-name-text" style="opacity:.7">${esc(a.displayVersion || '—')}</span></td>
          <td class="finder-col-size" style="width:150px">
            <button class="btn btn-secondary btn-small" data-un-app="${esc(a.id)}"${a.removable === false ? ' disabled data-tip="系统声明的不可移除包"' : ''}>卸载</button>
          </td>
        </tr>`).join('');
      return `<div class="finder-group-header"><span>${title} · ${list.length} 项</span></div>
        <table class="finder-table">
          <thead><tr><th>应用名</th><th class="finder-col-size" style="width:190px">发布者</th><th class="finder-col-size" style="width:130px">版本</th><th class="finder-col-size" style="width:150px">操作</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`;
    };
    return section('第三方应用', third) + section('Windows 应用', sys);
  }

  // ==================== 卸载 ====================
  async function runUninstall(appId) {
    const app = apps.find((a) => a.id === appId);
    if (!app || running) return;
    const isAppx = appId.startsWith('APPX|');
    // B1（2026-09-28 二轮拍板）：静默勾选框已删，静默优先是后端默认行为——
    // 前端不再传 silent 参数，卸载方式由后端按安装器类型裁决并经 usedSilent/fellBack 回传。
    const ok = await window.app?.confirmDanger?.(
      '确认卸载',
      isAppx
        ? `将从当前用户移除 Windows 应用「${app.displayName}」（Remove-AppxPackage，不弹确认界面）。`
        : `将卸载「${app.displayName}」：支持静默的安装器（msi/inno/nsis）先尝试静默卸载，否则自动弹出原厂卸载界面，按其提示操作。`,
      '开始卸载',
      '取消',
      isAppx
        ? '移除后其 %LOCALAPPDATA%\\Packages\\<包名> 应用数据将进入残留扫描候选，可一并清理（进回收站，可还原）。'
        : '卸载是不可逆操作；完成后 Trim 会自动复查卸载结果并提供残留扫描。'
    );
    if (!ok) return;
    running = true;
    startFakeProgress(isAppx ? '正在移除 Windows 应用…' : '卸载器运行中…等待卸载完成');
    try {
      const resp = await window.api.uninstall.run(appId);
      if (!resp.success) throw new Error(resp.message || '卸载失败');
      const d = resp.data || {};
      if (isAppx) {
        window.app?.toast?.('success', `「${app.displayName}」已移除`);
      } else if (d.stillListed) {
        window.app?.toast?.('warning', '卸载器已退出，但该程序仍在卸载列表中（可能未完成或已取消）');
      } else if (d.fellBack) {
        window.app?.toast?.('success', '静默卸载未完成，已回退原厂卸载界面并执行完毕，可以继续扫描残留');
      } else if (d.usedSilent) {
        window.app?.toast?.('success', '静默卸载完成，可以继续扫描残留');
      } else {
        window.app?.toast?.('success', '卸载完成，可以继续扫描残留');
      }
      await loadApps();
      // 卸载完成后自动扫残留（U-4 拍板 2026-09-28：Appx 移除后 Packages 孤儿数据并入扫描）
      currentAppId = appId;
      await scanResidue();
    } catch (e) {
      window.app?.toast?.('error', '卸载失败: ' + (e.message || e));
    } finally {
      finishFakeProgress();
      running = false;
    }
  }

  function setBusy(busy, label) {
    const overlay = document.getElementById('uninstallBusy');
    if (overlay) {
      overlay.style.display = busy ? 'block' : 'none';
      if (label) overlay.querySelector('.progress-label').textContent = label;
    }
  }

  // ==================== 自我安慰式进度（用户拍板 2026-09-28） ====================
  // 「Windows应用」枚举（Get-AppxPackage 子进程）耗时秒级且无真百分比——
  // 纯文字「正在枚举…」观感是卡死。改为进度条：从 5% 缓慢爬升封顶 99%，
  // 完成即 100% 收尾隐藏。卸载等待也复用同一条（卸载器耗时未知，同口径）。
  let busyTicker = null;

  function startFakeProgress(label) {
    stopFakeProgress();
    const overlay = document.getElementById('uninstallBusy');
    if (!overlay) return;
    overlay.style.display = 'block';
    if (label) overlay.querySelector('.progress-label').textContent = label;
    const fill = overlay.querySelector('.progress-fill');
    let v = 5;
    busyTicker = setInterval(() => {
      v = Math.min(99, v + Math.max(0.3, (99 - v) * 0.02));
      if (fill) fill.style.width = v + '%';
    }, 350);
  }

  function finishFakeProgress() {
    stopFakeProgress();
    const fill = document.querySelector('#uninstallBusy .progress-fill');
    if (fill) fill.style.width = '100%';
    setTimeout(() => {
      const overlay = document.getElementById('uninstallBusy');
      if (overlay) overlay.style.display = 'none';
      if (fill) fill.style.width = '0%';
    }, 350);
  }

  function stopFakeProgress() {
    if (busyTicker) { clearInterval(busyTicker); busyTicker = null; }
  }

  // ==================== 残留扫描 ====================
  async function scanResidue() {
    if (!currentAppId) return;
    residueMode = 'app';
    const panel = document.getElementById('residuePanel');
    const box = document.getElementById('residueList');
    panel.style.display = 'block';
    box.innerHTML = '<div class="finder-empty">正在扫描残留…</div>';
    // U-8 感知修复：面板在长列表下方，不滚动就等于"没弹出"——扫完直接滚到面板
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    try {
      const resp = await window.api.uninstall.residueScan(currentAppId);
      if (!resp.success) throw new Error(resp.message || '残留扫描失败');
      findings = resp.data.findings || [];
      const name = resp.data.appName || '';
      document.getElementById('residueTitle').textContent = name ? `残留扫描 · ${name}` : '残留扫描';
      renderResidue();
      // U-8：无残留也明确说一声（面板已滚入视野，toast 兜底双重感知）
      window.app?.toast?.(findings.length ? 'info' : 'success',
        findings.length ? `发现 ${findings.length} 项残留，请在下方确认后清理` : '未发现残留，程序卸载得很干净');
    } catch (e) {
      box.innerHTML = `<div class="finder-empty">残留扫描失败：${esc(String(e.message || e))}</div>`;
      window.app?.toast?.('error', '残留扫描失败: ' + (e.message || e));
    }
  }

  // C2 孤儿应用数据扫描：只按「本机确实卸载过它」这条所有权链出候选。
  // 后端在档案为空、程序清单取不到、进程快照取不到时都会**拒绝扫描**而不是回空集——
  // 空集会被读成「这台机器没有孤儿」，那是把"不知道"伪装成"知道"。
  async function scanOrphans() {
    const panel = document.getElementById('residuePanel');
    const box = document.getElementById('residueList');
    residueMode = 'orphan';
    currentAppId = ORPHAN_APP_ID;
    panel.style.display = 'block';
    box.innerHTML = '<div class="finder-empty">正在按卸载记录比对…</div>';
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    try {
      const resp = await window.api.uninstall.orphanScan();
      if (!resp.success) throw new Error(resp.message || '孤儿扫描失败');
      findings = resp.data.findings || [];
      document.getElementById('residueTitle').textContent = '孤儿应用数据';
      renderResidue();
      window.app?.toast?.(findings.length ? 'info' : 'success',
        findings.length ? `发现 ${findings.length} 项遗留可弃目录，均未自动勾选，请逐项确认` : '没有符合所有权判定的遗留目录');
    } catch (e) {
      box.innerHTML = `<div class="finder-empty">孤儿扫描未执行：${esc(String(e.message || e))}</div>`;
      window.app?.toast?.('warning', '孤儿扫描未执行: ' + (e && e.message ? e.message : String(e)));
    }
  }

  async function ignoreOrphanOwner(f) {
    try {
      const resp = await window.api.uninstall.orphanIgnore(f.ownerAppId, f.ownerName || '');
      if (!resp || !resp.success) throw new Error((resp && resp.message) || '写入忽略记录失败');
      window.app?.toast?.('success', `已不再提示「${esc(f.ownerName || '')}」的遗留数据`);
      await scanOrphans();
    } catch (e) {
      window.app?.toast?.('error', '忽略失败: ' + (e && e.message ? e.message : String(e)));
    }
  }

  function renderResidue() {
    const box = document.getElementById('residueList');
    if (!findings.length) {
      box.innerHTML = '<div class="finder-empty">未发现残留。程序卸载得很干净。</div>';
      updateResidueButtons();
      return;
    }
    // 树形两段：注册表 / 文件与目录（方案 §4.6 的分组语义，MVP 先按类型两段）
    // reg_value 为 U-2 侧痕（MuiCache/防火墙/BAM 单值删除），归注册表段
    const regs = findings.filter((f) => f.kind === 'reg_key' || f.kind === 'reg_value');
    const files = findings.filter((f) => f.kind !== 'reg_key');
    let html = '';
    const section = (title, rows, prefix) => {
      if (!rows.length) return '';
      let h = `<div class="finder-group-header"><span>${title} · ${rows.length} 项</span></div>`;
      h += '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>目标</th><th style="width:110px">置信度</th><th style="width:200px">判定原因</th></tr></thead><tbody>';
      for (const f of rows) {
        const checked = !!f.defaultChecked;
        // C2 孤儿行的处置出口：所有权判定可能有误（同名的另一款软件、或用户自己放的数据），
        // 必须能让用户把某个历史 owner 永久排除，而不是每次扫描都重复看到同一条
        const ignoreBtn = f.origin === 'orphan'
          ? `<button class="btn btn-secondary" style="margin-left:8px;padding:2px 8px;font-size:12px" data-orphan-ignore="${findings.indexOf(f)}" data-tip="此后不再按这条卸载记录提示遗留数据（只影响孤儿扫描，不动残留规则库）">不再提示该程序</button>`
          : '';
        h += `<tr class="${checked ? 'finder-row-selected' : ''}">
          <td><span class="checkbox ${checked ? 'checked' : ''}" data-rcheck="${prefix}"></span></td>
          <td><div class="finder-cell"><span class="finder-path-text" data-tip="${esc(f.target)}">${esc(f.target)}</span></div></td>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.75">${CONF_LABEL[f.confidence] || f.confidence || '—'}</span></td>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.75">${esc(f.reason || '')}</span>${ignoreBtn}</td>
        </tr>`;
      }
      h += '</tbody></table>';
      return h;
    };
    html += section('注册表', regs, 'reg');
    html += section('文件与目录', files, 'file');
    box.innerHTML = html;
    // 勾选状态记在 finding 对象上（defaultChecked 为初始值）
    findings.forEach((f) => { if (typeof f._checked === 'undefined') f._checked = !!f.defaultChecked; });
    updateResidueButtons();
  }

  function onResidueClick(e) {
    const ign = e.target.closest('[data-orphan-ignore]');
    if (ign) {
      const target = findings[Number(ign.dataset.orphanIgnore)];
      if (target) ignoreOrphanOwner(target);
      return;
    }
    const t = e.target.closest('[data-rcheck]');
    if (!t) return;
    const isReg = t.dataset.rcheck === 'reg';
    const regs = findings.filter((f) => f.kind === 'reg_key' || f.kind === 'reg_value');
    const files = findings.filter((f) => f.kind !== 'reg_key');
    const rows = isReg ? regs : files;
    const idx = Array.from(t.closest('tbody').querySelectorAll('[data-rcheck]')).indexOf(t);
    const f = rows[idx];
    if (!f) return;
    f._checked = !f._checked;
    t.classList.toggle('checked', f._checked);
    t.closest('tr').classList.toggle('finder-row-selected', f._checked);
    updateResidueButtons();
  }

  function updateResidueButtons() {
    const any = findings.some((f) => f._checked);
    document.getElementById('residueBtnClean').disabled = !any;
  }

  // ==================== 残留清理 ====================
  async function cleanResidue() {
    const picked = findings.filter((f) => f._checked);
    if (!picked.length || running) return;
    const ok = await window.app?.confirmDanger?.(
      '确认清理残留',
      `将删除选中的 ${picked.length} 项残留。文件与目录移入回收站（可还原）；注册表项删除前自动导出备份。`,
      '开始清理',
      '取消',
      '低置信项为名称启发式结果，请确认路径确实属于已卸载的程序再勾选。'
    );
    if (!ok) return;
    running = true;
    setBusy(true, '正在清理残留…');
    startFakeProgress('正在清理残留…');
    try {
      const resp = await window.api.uninstall.residueExecute(
        currentAppId,
        picked.map((f) => ({ kind: f.kind, target: f.target }))
      );
      if (!resp.success) throw new Error(resp.message || '残留清理失败');
      const d = resp.data || {};
      const okCount = Number(d.okCount) || 0;
      const failCount = Number(d.failCount) || 0;
      if (failCount > 0) {
        window.app?.toast?.('warning', `残留清理完成：${okCount} 项成功，${failCount} 项失败（详见报告）`);
      } else {
        window.app?.toast?.('success', `残留清理完成：${okCount} 项已处理`);
      }
      // 成功项从面板移除，重渲染
      const done = new Set((d.details || []).filter((x) => x.status === 'ok').map((x) => x.kind + '|' + x.target));
      findings = findings.filter((f) => !done.has(f.kind + '|' + f.target));
      renderResidue();
      await loadApps();
    } catch (e) {
      window.app?.toast?.('error', '残留清理失败: ' + (e.message || e));
    } finally {
      stopFakeProgress();
      setBusy(false);
      running = false;
    }
  }

  // ==================== U-6 批次报告查看 ====================

  function closeReportModal() {
    document.getElementById('unReportBackdrop')?.remove();
  }

  async function renderReportList(ctrl) {
    const body = ctrl.body;
    let resp;
    try {
      resp = await window.api.uninstall.reportList();
    } catch (e) {
      if (document.body.contains(body)) body.innerHTML = `<div class="finder-empty">报告读取失败: ${esc(e.message || e)}</div>`;
      return;
    }
    if (!document.body.contains(body)) return;
    const reports = (resp && resp.success && resp.data && resp.data.reports) || [];
    if (!reports.length) {
      body.innerHTML = '<div class="finder-empty">还没有残留清理报告。执行一次「删除选中残留」后会自动生成。</div>';
      return;
    }
    body.innerHTML = `<table class="finder-table"><thead><tr><th>时间</th><th style="width:230px">目标程序（卸载键）</th><th class="finder-col-size" style="width:170px">成功/失败/跳过</th><th class="finder-col-size" style="width:80px">明细</th></tr></thead><tbody>${
      reports.map((r, i) => `
        <tr>
          <td><span class="finder-name-text" style="opacity:.8">${esc(r.time || r.batchId)}</span></td>
          <td><span class="finder-name-text" style="opacity:.8" data-tip="${esc(r.appId || '')}">${esc(r.appId || '—')}</span></td>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.8">${r.okCount} / ${r.failCount} / ${r.skipCount}</span></td>
          <td class="finder-col-size"><button class="fileclean-preview-btn" data-report-view="${i}" type="button">查看</button></td>
        </tr>`).join('')
    }</tbody></table>`;
    body.querySelectorAll('[data-report-view]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const r = reports[+btn.getAttribute('data-report-view')];
        if (r) openReportDetail(r.batchId, ctrl);
      });
    });
  }

  async function openReportDetail(batchId, ctrl) {
    let resp;
    try {
      resp = await window.api.uninstall.reportGet(batchId);
    } catch (e) {
      window.app?.toast?.('error', '报告读取失败: ' + (e.message || e));
      return;
    }
    if (!resp || !resp.success) {
      window.app?.toast?.('error', (resp && resp.message) || '报告读取失败');
      return;
    }
    const body = ctrl.body;
    if (!document.body.contains(body)) return;
    const data = resp.data || {};
    const details = Array.isArray(data.details) ? data.details : [];
    const statusLabel = { ok: '成功', fail: '失败', skip: '跳过' };
    body.innerHTML = `
      <div class="finder-group-header"><span>批次 ${esc(batchId)} · ${esc(data.appId || '')}</span></div>
      ${details.length ? `<table class="finder-table"><thead><tr><th class="finder-col-size" style="width:70px">结果</th><th>目标</th><th style="width:220px">说明</th></tr></thead><tbody>${details.map((d) => `
        <tr>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.8">${esc(statusLabel[d.status] || d.status || '—')}</span></td>
          <td><span class="finder-path-text" data-tip="${esc(d.target || '')}">${esc(d.target || '—')}</span></td>
          <td><span class="finder-name-text" style="opacity:.8">${esc(d.message || '')}</span></td>
        </tr>`).join('')}</tbody></table>` : '<div class="finder-empty">该批次没有明细记录。</div>'}
      <div style="margin-top:10px"><button class="btn btn-secondary btn-small" data-report-back type="button">← 返回报告列表</button></div>`;
    body.querySelector('[data-report-back]').addEventListener('click', () => renderReportList(ctrl));
  }

  function openReportManager() {
    closeReportModal();
    const ctrl = window.modal.create({
      id: 'unReportBackdrop',
      title: '残留清理报告',
      bodyHtml: '<div class="finder-empty">正在读取报告列表…</div>',
      footerClass: 'pw-footer',
      footerHtml: '<button class="btn btn-secondary" data-role="doneBtn" type="button">关闭</button>'
    });
    ctrl.footer.querySelector('[data-role="doneBtn"]').addEventListener('click', closeReportModal);
    renderReportList(ctrl);
  }

  // ==================== 初始化 ====================
  // A3（M3）残留规则库在线更新：刻意做成显式动作、不做定时自动更新——规则库决定
  // 「什么会被当成残留」，替换它必须是用户点出来的一次操作（删除本身仍要逐项勾选 +
  // 快照复核 + 注册表先备份，硬闸在后端）。失败必须可见：清理域 v0.2.2 修过
  // 「异步失败被同步 try/catch 静默吞掉」那一类缺陷，这里不重犯。
  let rulesUpdating = false;

  async function updateResidueRules() {
    if (rulesUpdating) return;
    const btn = document.getElementById('btnResidueRulesUpdate');
    rulesUpdating = true;
    if (btn) btn.disabled = true;
    try {
      const chk = await window.api.uninstall.checkResidueVersion();
      if (!chk || !chk.success) throw new Error((chk && chk.message) || '检查版本失败');
      const cur = chk.data.currentVersion;
      if (!chk.data.newerAvailable) {
        window.app?.toast?.('info', `残留规则库已是最新（版本 ${esc(String(cur))}）`);
        return;
      }
      const up = await window.api.uninstall.updateResidueRules();
      if (!up || !up.success) throw new Error((up && up.message) || '更新失败');
      window.app?.toast?.(
        'success',
        `残留规则库已更新：${esc(String(cur))} → ${esc(String(up.data.rulesVersion))}，重新扫描后生效`
      );
      // 面板已展开时立刻按新规则重扫，免得用户以为「更新了但还是那几条」
      if (currentAppId) await scanResidue();
    } catch (e) {
      window.app?.toast?.('error', '残留规则库更新失败: ' + (e && e.message ? e.message : String(e)));
    } finally {
      rulesUpdating = false;
      if (btn) btn.disabled = false;
    }
  }

  function init() {
    if (inited) return;
    inited = true;
    document.querySelectorAll('[data-un-scope]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.dataset.unScope === currentScope) return;
        currentScope = btn.dataset.unScope;
        document.querySelectorAll('[data-un-scope]').forEach((b) => {
          b.classList.toggle('active', b.dataset.unScope === currentScope);
          b.setAttribute('aria-selected', b.dataset.unScope === currentScope ? 'true' : 'false');
        });
        // 切换范围时收起残留面板（上一范围的扫描结果对另一范围无意义）
        const panel = document.getElementById('residuePanel');
        if (panel) panel.style.display = 'none';
        loadApps();
      });
    });
    document.getElementById('uninstallBtnRefresh')?.addEventListener('click', loadApps);
    document.getElementById('btnUninstallReports')?.addEventListener('click', openReportManager);
    document.getElementById('btnResidueRulesUpdate')?.addEventListener('click', updateResidueRules);
    document.getElementById('uninstallList')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-un-app]');
      if (btn && !btn.disabled) runUninstall(btn.dataset.unApp);
    });
    // 「重新扫描」按面板当前来源回到对应的扫描链：孤儿扫描不能把面板又变回单程序残留
    document.getElementById('residueBtnRescan')?.addEventListener('click', () => {
      if (residueMode === 'orphan') { scanOrphans(); } else { scanResidue(); }
    });
    document.getElementById('btnUninstallOrphans')?.addEventListener('click', scanOrphans);
    document.getElementById('residueBtnClean')?.addEventListener('click', cleanResidue);
    document.getElementById('residueList')?.addEventListener('click', onResidueClick);
    loadApps();
  }

  window.uninstall = { init };

  // 进页动态注入时 readyState 已是 complete/interactive，直接初始化（check-idle-scripts 口径）
  if (document.readyState !== 'loading') { init(); }
  else document.addEventListener('DOMContentLoaded', init);
})();
