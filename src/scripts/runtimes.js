// runtimes.js - 运行库修复（v3.3.0 第一期）
// 三段式页面：说明区（index.html 静态）+ 中心雷达图（内联 SVG，token 化）+ 条目列表。
// 全程只读检测；一键修复走 confirmDanger 红色确认 → install（只传 actionId）→
// 主进程下载（白名单+双校验）+ 静默安装 → 返回最新 items 直接刷新。
// 链路骨架复刻 netcheck.js；第一期覆盖 VC++ / .NET / DirectX 三大类（方案 §2）。
(function () {
  'use strict';

  const escapeHtml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // 条目元数据：名称 / 说明 / 雷达节点归属（node: vc | dx | net）
  const ITEM_META = {
    'vc-x64': { name: 'VC++ 运行库（x64）', desc: '64 位程序依赖的 C++ 运行库（2015-2022 统一版本 14.x）', node: 'vc' },
    'vc-x86': { name: 'VC++ 运行库（x86）', desc: '32 位程序依赖的 C++ 运行库（2015-2022 统一版本 14.x）', node: 'vc' },
    'netfx4x': { name: '.NET Framework 4.x', desc: '大量桌面软件依赖的 .NET 运行时（4.5-4.8.1）', node: 'net' },
    'netfx35': { name: '.NET Framework 3.5', desc: '部分老游戏 / 老软件需要（Windows 可选功能）', node: 'net' },
    'dx9': { name: 'DirectX 旧版组件', desc: 'DirectX 9.0c 附属库与 DX12 系统组件', node: 'dx' },
    'vc-old': { name: '旧版 VC++（2005-2013）', desc: '信息级：仅列出已装版本，不判定异常', node: null }
  };

  const STATUS_LABEL = {
    idle: '等待扫描', scanning: '扫描中', ok: '正常', warn: '警告', fail: '异常',
    info: '信息', unknown: '未验证'
  };

  const NODE_LABELS = { vc: 'VC++ 2015-2022', dx: 'DirectX 9-12', net: '.NET Framework' };
  // 组内最差状态决定雷达节点颜色（fail > warn > ok > 未扫描）
  const RANK = { fail: 0, warn: 1, ok: 2, info: 3, unknown: 4, scanning: 5, idle: 6 };

  let items = [];          // 最近一次检测结果
  let scanning = false;
  const repairedSet = new Set(); // v3.5.3：本会话修复成功的条目（行内「已修复」标记）

  // ==================== 雷达图 ====================
  function renderRadar() {
    const mount = document.getElementById('rtRadar');
    if (!mount) return;
    mount.innerHTML = `
      <svg viewBox="0 0 680 430" class="rt-radar-svg" role="img" aria-label="运行库状态雷达图">
        <circle cx="340" cy="215" r="46" fill="none" stroke="var(--border-default)" stroke-width="1"/>
        <circle cx="340" cy="215" r="82" fill="none" stroke="var(--border-default)" stroke-width="1"/>
        <circle cx="340" cy="215" r="118" fill="none" stroke="var(--border-default)" stroke-width="1"/>
        <circle cx="340" cy="215" r="4" fill="var(--accent)" opacity="0.35"/>
        <g class="rt-sweep" style="transform-origin:340px 215px">
          <line x1="340" y1="215" x2="340" y2="97" stroke="var(--accent)" stroke-width="1" opacity="0.5"/>
        </g>
        <g class="rt-node" data-node="vc">
          <line x1="252" y1="188" x2="206" y2="170" stroke="var(--border-default)" stroke-width="1"/>
          <circle class="rt-node-ring" cx="252" cy="188" r="8" fill="none" stroke="var(--fg-tertiary)" stroke-width="1.2"/>
          <circle class="rt-node-dot" cx="252" cy="188" r="3.5" fill="var(--fg-tertiary)"/>
          <text class="rt-node-name" x="198" y="168" text-anchor="end">${NODE_LABELS.vc}</text>
          <text class="rt-node-state" x="198" y="186" text-anchor="end">未扫描</text>
        </g>
        <g class="rt-node" data-node="dx">
          <line x1="452" y1="158" x2="492" y2="136" stroke="var(--border-default)" stroke-width="1"/>
          <circle class="rt-node-ring" cx="444" cy="162" r="8" fill="none" stroke="var(--fg-tertiary)" stroke-width="1.2"/>
          <circle class="rt-node-dot" cx="444" cy="162" r="3.5" fill="var(--fg-tertiary)"/>
          <text class="rt-node-name" x="498" y="132">${NODE_LABELS.dx}</text>
          <text class="rt-node-state" x="498" y="150">未扫描</text>
        </g>
        <g class="rt-node" data-node="net">
          <line x1="440" y1="286" x2="478" y2="310" stroke="var(--border-default)" stroke-width="1"/>
          <circle class="rt-node-ring" cx="432" cy="280" r="8" fill="none" stroke="var(--fg-tertiary)" stroke-width="1.2"/>
          <circle class="rt-node-dot" cx="432" cy="280" r="3.5" fill="var(--fg-tertiary)"/>
          <text class="rt-node-name" x="484" y="318">${NODE_LABELS.net}</text>
          <text class="rt-node-state" x="484" y="336">未扫描</text>
        </g>
      </svg>`;
  }

  // 用检测结果驱动雷达节点状态（组内取最差状态）
  function updateRadar() {
    const states = {};
    for (const it of items) {
      const meta = ITEM_META[it.id];
      if (!meta || !meta.node) continue;
      const cur = states[meta.node];
      if (!cur || (RANK[it.status] ?? 9) < (RANK[cur] ?? 9)) states[meta.node] = it.status;
    }
    for (const node of ['vc', 'dx', 'net']) {
      const el = document.querySelector(`.rt-node[data-node="${node}"]`);
      if (!el) continue;
      const st = states[node] || 'unknown';
      el.classList.remove('ok', 'warn', 'fail', 'unknown', 'scanning');
      el.classList.add(st === 'info' ? 'unknown' : st);
      const label = st === 'scanning' ? '扫描中…' : (STATUS_LABEL[st] || '未扫描');
      el.querySelector('.rt-node-state').textContent = label;
    }
  }

  // ==================== 条目列表 ====================
  function renderList() {
    const root = document.getElementById('runtimesList');
    if (!root) return;
    if (!items.length) {
      root.innerHTML = `<div class="empty-state"><p>尚未扫描。点击「开始扫描」检测本机运行库状态。</p></div>`;
      return;
    }
    root.innerHTML = items.map(it => {
      const meta = ITEM_META[it.id] || { name: it.id, desc: '' };
      const evid = Array.isArray(it.evidence) ? it.evidence : [];
      const canRepair = !!(it.repair && it.repair.id);
      const fixed = repairedSet.has(it.id) && it.status === 'ok' ? '<span class="rt-fixed-badge" data-tip="本次会话已修复成功">已修复</span>' : '';
      const repairBtn = canRepair
        ? `<button type="button" class="btn btn-danger btn-small rt-repair-btn" data-rt-repair="${escapeHtml(it.repair.id)}" data-rt-name="${escapeHtml(it.repair.name || meta.name)}">一键修复</button>`
        : (it.status === 'fail' ? '<span class="rt-no-repair" data-tip="微软官方已下架独立安装包，建议通过安装含 DirectX 9 的游戏补齐，或使用系统文件修复">暂无一键修复</span>' : '');
      return `
      <div class="rt-item" data-id="${escapeHtml(it.id)}">
        <div class="rt-item-head">
          <span class="rt-badge ${it.status}">${STATUS_LABEL[it.status] || it.status}</span>
          <div class="rt-item-copy">
            <div class="rt-item-name">${escapeHtml(meta.name)}</div>
            <div class="rt-item-desc">${escapeHtml(meta.desc)}</div>
          </div>
          ${fixed}${repairBtn}
        </div>
        ${evid.length ? `<div class="rt-item-evidence">${evid.map(e => `<div class="rt-evidence-row">${escapeHtml(e)}</div>`).join('')}</div>` : ''}
      </div>`;
    }).join('');
    root.querySelectorAll('[data-rt-repair]').forEach(btn => {
      btn.addEventListener('click', () => repairFlow(btn.dataset.rtRepair, btn.dataset.rtName));
    });
  }

  function renderSummary(summary) {
    const el = document.getElementById('rtSummary');
    if (!el) return;
    if (!summary) { el.textContent = '尚未扫描 · 点击「开始扫描」检测本机运行库'; return; }
    if (summary.fail === 0 && summary.warn === 0) {
      el.textContent = `共 ${summary.total} 项，全部正常`;
      el.classList.add('all-ok');
    } else {
      el.textContent = `共 ${summary.total} 项：${summary.ok} 项正常 · ${summary.warn} 项警告 · ${summary.fail} 项异常`;
      el.classList.remove('all-ok');
    }
  }

  // ==================== 扫描 ====================
  async function startCollect(silent) {
    if (scanning) return;
    if (!window.api?.runtimes?.collect) {
      window.app?.toast('warning', '当前环境不支持运行库检测');
      return;
    }
    scanning = true;
    const btn = document.getElementById('btnRuntimesScan');
    if (btn) { btn.disabled = true; btn.dataset.origText = btn.textContent; btn.textContent = '扫描中…'; }
    items = [{ id: 'placeholder', status: 'scanning' }];
    // 扫描中：列表骨架 + 雷达节点转扫描态
    renderRadar();
    updateRadar();
    const root = document.getElementById('runtimesList');
    if (root && window.ds) root.innerHTML = window.ds.skeletonRows(6);
    else if (root) root.innerHTML = '<div class="empty-state"><p>正在扫描运行库…</p></div>';
    // 复核 RT-5（2026-09-16）：原为 renderSummary(null) 后紧接覆盖 textContent='扫描中…' 的冗余双写，
    // 删除 renderSummary(null) 调用，只保留「扫描中…」一次设置（错误路径仍有 renderSummary(null) 兜底）。
    document.getElementById('rtSummary') && (document.getElementById('rtSummary').textContent = '扫描中…');
    try {
      const resp = await window.api.runtimes.collect();
      if (!resp || !resp.success) throw new Error((resp && resp.message) || '运行库检测失败');
      items = resp.data.items;
      renderList();
      updateRadar();
      renderSummary(resp.data.summary);
      if (!silent) window.app?.toast('success', `运行库扫描完成，共 ${resp.data.summary.total} 项`);
    } catch (e) {
      items = [];
      renderList();
      updateRadar();
      renderSummary(null);
      window.app?.toast('error', '运行库检测失败: ' + e.message);
    } finally {
      scanning = false;
      if (btn) { btn.disabled = false; btn.textContent = btn.dataset.origText || '开始扫描'; }
    }
  }

  // ==================== 修复流程 ====================
  // 红色二次确认（列出动作/来源/体积/是否需重启）→ install（只传 actionId）→
  // needAdmin 时走 requestElevation 握手 → 结果直接刷新列表与雷达
  async function repairFlow(actionId, actionName) {
    if (!window.api?.runtimes?.install) {
      window.app?.toast('warning', '当前环境不支持运行库修复');
      return;
    }
    const ok = await window.app?.confirm?.(
      `安装「${actionName}」`,
      '将从微软官方直链下载安装包（经来源白名单与 SHA-256 校验）后静默安装。\n' +
      '该操作需要管理员权限，部分组件安装后可能需要重启电脑才能完全生效。\n\n确认开始修复？',
      '确认安装',
      '取消',
      { danger: true, dangerHint: '安装程序来自微软官方直链并经哈希校验；请仅在理解用途后执行。' }
    );
    if (!ok) return;
    // v3.5.3：重渲染会重建列表节点，先锁定目标条目 id（id 跨扫描稳定）
    const targetItem = items.find(x => x.repair && x.repair.id === actionId);
    const btn = document.querySelector(`[data-rt-repair="${actionId}"]`);
    if (btn) { btn.disabled = true; btn.textContent = '准备中…'; }
    const unbind = window.api.runtimes.onProgress?.((d) => {
      if (btn) {
        if (d.phase === 'download') btn.textContent = d.cached ? '使用缓存…' : `下载中 ${d.percent}%`;
        else btn.textContent = '安装中…';
      }
    });
    try {
      const resp = await window.api.runtimes.install(actionId);
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('运行库修复需要管理员权限才能安装系统组件。');
        if (elevated) {
          window.app?.toast('info', '已获得管理员权限，请重新点击「一键修复」');
        }
        return;
      }
      if (resp && resp.success) {
        // 复核 N1（运行库，2026-09-16）：repairedSet 此前只声明读取从未 add，「已修复」徽标永不显示；
        // 修复成功后按目标条目 id 记账，重扫后 status==='ok' 时行内展示徽标（会话级，跨扫描保留）。
        if (targetItem) repairedSet.add(targetItem.id);
        window.app?.toast('success', `「${actionName}」修复完成`);
      } else {
        window.app?.toast('error', (resp && resp.message) || `「${actionName}」修复未成功`);
      }
      if (resp && Array.isArray(resp.items) && resp.items.length) {
        items = resp.items;
        renderList();
        updateRadar();
        renderSummary(resp.summary);
      }
      // v3.5.3：修复成功后只读复检一次，按钮与状态按最新事实重建；
      // 需重启才生效的组件会保留修复入口并给出提示（不再出现「修复成功但按钮消失」的死端）。
      if (resp && resp.success) {
        await startCollect(true);
        const after = targetItem ? items.find(x => x.id === targetItem.id) : null;
        if (after && after.status !== 'ok') {
          window.app?.toast('info', `「${actionName}」已安装；部分组件需重启电脑后完全生效`);
        }
      }
    } catch (e) {
      window.app?.toast('error', '修复异常: ' + e.message);
    } finally {
      unbind?.();
      if (btn) { btn.disabled = false; btn.textContent = '一键修复'; }
    }
  }

  // ==================== 初始化 ====================
  function init() {
    renderRadar();
    renderList();
    document.getElementById('btnRuntimesScan')?.addEventListener('click', startCollect);
  }

  // 首次进入页面自动扫描一次（只读检测，无副作用；结果不入持久缓存——运行库状态随系统变化低频但真实）
  function onEnter() {
    if (!items.length && !scanning) startCollect();
  }

  window.runtimes = { init, onEnter, startCollect };
})();
