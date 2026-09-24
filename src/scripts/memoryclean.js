// memoryclean.js - 内存清理模块
// 参考 Mem Reduct：按内存区域（工作集/修改列表/备用列表/低优先级备用列表/合并物理内存页）
// 勾选清理；区域条目点击弹窗查看详细简介（复用启动项管理的交互）。
// 「运行中的进程」入口精简为「去管理」按钮，详细列表在独立「应用进程管理」窗口展示
// （见 process-manager-window.js + processes.js）。
(function () {
  'use strict';

  const $ = id => document.getElementById(id);

  // 内存清理区域定义（与 memory-scripts.js 的 cleanScript 顺序保持一致）
  // 注：系统文件缓存(82)、注册表缓存(84) 在 Windows 11 27H2 上系统级不可用，已移除
  // 顽固软件专杀(kind:'stubborn') 走独立脚本（memory:stubborn-kill），非内存区清理。
  const REGIONS = [
    { id: 'workingSet', name: '进程工作集', risk: 'low', checked: true,
      desc: '逐进程收紧内存工作集，系统进程与游戏自动跳过，最常用' },
    { id: 'standbyPriority0', name: '低优先级待机', risk: 'low', checked: true,
      desc: '仅清理 0 优先级待机页，不影响常用缓存，安全' },
    { id: 'combine', name: '即时合并物理内存页', risk: 'medium', checked: true,
      desc: '此刻调用 NtSetSystemInformation(87) 合并物理内存页去重，降低页表开销，Win10+ 可用；与「电脑优化中心 - 关闭 Windows 内存页合并（PageCombining）」不是同一机制，互不影响' },
    { id: 'modified', name: '修改页面列表', risk: 'high', checked: true,
      desc: '脏页写盘后回收，触发磁盘 I/O，可能短暂卡顿' },
    { id: 'standby', name: '待机列表', risk: 'high', checked: true,
      desc: 'SuperFetch 预读缓存，回收最安全、释放量大' },
    // 系统文件缓存(82)、注册表缓存(84)：Windows 11 27H2 上系统级调用返回错误，不可清理，
    // 仅作灰显说明展示（sysUnavailable），不进入可清理/勾选流程。
    { id: 'fileCache', name: '系统文件缓存', sysUnavailable: true,
      desc: '压低缓存上限强制回收文件页（当前系统版本不可用）' },
    { id: 'registryCache', name: '注册表缓存', sysUnavailable: true,
      desc: '注册表预读缓存（Win8.1+ 可用，当前系统版本不可用）' },
    // N1（2026-09-14 重复点审查）：原「顽固软件专杀」与「电脑优化中心 - 顽固软件策略专杀」
    // 合并为同一张「顽固软件治理」卡片，分两层：勾选 /「立即结束进程」= 一次性杀进程；
    // 「阻止开机自启」= 常驻服务改手动 + 删 WPS 更新任务（持久，不提供自动还原）。
    { id: 'stubbornKill', name: '顽固软件治理', risk: 'medium', checked: true, kind: 'stubborn',
      desc: '两层处理：①「立即结束进程」一次性结束 MuMu 模拟器 / 网易 UU 远程 / 抖音 / 剪映 / WPS 金山办公 / 微软电脑管家 的后台常驻与守护进程（含前台进程，请先保存工作）；②「阻止开机自启」把这些软件的后台服务改为手动启动，并删除 WPS 更新计划任务、关闭其自动升级（持久生效，不提供自动还原）' }
  ];

  const RISK_LABELS = { low: '低风险', medium: '中风险', high: '高风险' };

  let maximized = false;     // 窗口最大化（指标卡一行展示）

  function escapeHtml(s) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => map[m]);
  }
  function escapeAttr(s) {
    return String(s == null ? '' : s).replace(/"/g, '&quot;').replace(/</g, '&lt;');
  }
  function fmtBytes(bytes) {
    if (!isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = bytes;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i <= 1 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }
  function fmtPercent(p) { return (isFinite(p) ? Math.round(p) : 0) + '%'; }
  function barColor(p) {
    if (p >= 90) return 'linear-gradient(90deg, #DC2626, #EF4444)';
    if (p >= 70) return 'linear-gradient(90deg, #D97706, #F59E0B)';
    return '';
  }
  function setBar(el, percent) {
    if (!el) return;
    const p = Math.max(0, Math.min(100, Number(percent) || 0));
    el.style.width = p + '%';
    el.style.background = barColor(p) || '';
  }

  // ==================== 指标卡（与系统概览同款 2x2 / 最大化一行） ====================
  function applyLayout() {
    const el = document.querySelector('.mem-metrics');
    if (el) el.classList.toggle('overview-maximized', maximized);
    fitMemValue();
  }
  if (window.api?.window?.onResized) {
    window.api.window.onResized((bounds) => {
      maximized = !!(bounds && bounds.maximized);
      applyLayout();
    });
  }

  // ==================== 内存信息 ====================
  async function loadInfo() {
    if (window.api?.memory) {
      try {
        const resp = await window.api.memory.info();
        if (resp && resp.success && resp.data) {
          renderInfo(resp.data);
          return;
        }
        throw new Error((resp && resp.message) || '读取失败');
      } catch (e) {
        window.app?.toast('error', '读取内存信息失败：' + e.message);
      }
    } else {
      // 浏览器预览模式模拟
      renderInfo({ total: 16 * 1073741824, free: 5.5 * 1073741824, used: 10.5 * 1073741824, load: 66, pageTotal: 8 * 1073741824, pageUsed: 3 * 1073741824, cache: 2.2 * 1073741824 });
    }
  }

  // 数值过长（如 11.2 GB / 15.7 GB 在四联卡宽度下折成三行）时自动缩小字号，
  // 最多两行封顶（CSS 侧另有 -webkit-line-clamp 兜底）；显示/尺寸变化经 ResizeObserver 重算。
  // v3.6.2 修复整页 20Hz 闪烁（ResizeObserver 自激振荡）：旧实现 observe #memUseValue
  // 自身，且每轮回调都无条件 fontSize='' 重置再 while 缩小——重置（变高）与缩小（变矮）
  // 各改写一次自身高度，RO 必然再次投递回调，形成「20px 大字 ↔ 12px 小字」逐帧横跳
  // （CDP 实测 1.6s 内回调 1675 次），卡片高度随之抖动并把下方整个列表顶得上下闪。
  // 两道护栏：① observe 不受字号影响的容器 .summary-info（改字号不反作用于其宽度，
  // 反馈环物理断开）；② 按「文本 + 容器宽度」签名拟合，签名不变零写入，收敛即停；
  // 容器变宽时签名变化，字号自然回弹。
  let fitSignature = '';
  function fitMemValue() {
    const el = $('memUseValue');
    if (!el) return;
    const box = el.closest('.summary-info') || el;
    const sig = el.textContent + '|' + box.clientWidth;
    if (fitSignature === sig) return; // 已按当前文本/宽度收敛：零写入，杜绝自激
    el.style.fontSize = ''; // 签名变化（新数值或容器改宽）：从 CSS 默认字号重新拟合
    const cs = getComputedStyle(el);
    const lh = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.2;
    const twoLines = lh * 2 + 1;
    let size = parseFloat(cs.fontSize);
    let guard = 16; // 16 档覆盖 --font-size-scale 放大（25px→12px 需 13 次）
    while (guard-- > 0 && el.scrollHeight > twoLines && size > 12) {
      size -= 1;
      el.style.fontSize = size + 'px';
    }
    fitSignature = sig;
  }
  if (window.ResizeObserver) {
    // observe 容器而非 #memUseValue 自身：字号只改元素自身高度，不影响容器宽度
    const fitBox = document.getElementById('memUseValue')?.closest('.summary-info');
    if (fitBox) new ResizeObserver(() => fitMemValue()).observe(fitBox);
  }

  function renderInfo(d) {
    const total = Number(d.total) || 0;
    const free = Number(d.free) || 0;
    const used = Number(d.used) || 0;
    const load = Number(d.load) || 0;

    // 环形进度已展示百分比（用户要求去掉重复：文字只保留字节数）；
    // ds 未加载（无环）时保留百分比前缀作为降级展示。
    const hasRing = ensureRing();
    const v = $('memUseValue');
    if (v) v.textContent = (hasRing ? '' : fmtPercent(load) + ' · ') + fmtBytes(used) + ' / ' + fmtBytes(total);
    fitMemValue();
    setBar($('memUseBar'), load);
    if (hasRing) setRingValue(load);

    const f = $('memFreeValue');
    if (f) f.textContent = fmtBytes(free);

    const pf = $('memPagefileValue');
    if (pf) {
      const pt = Number(d.pageTotal) || 0;
      const pfUsed = Number(d.pageUsed) || 0;
      pf.textContent = pt ? fmtBytes(pfUsed) + ' / ' + fmtBytes(pt) : '--';
    }

    const c = $('memCacheValue');
    if (c) c.textContent = fmtBytes(Number(d.cache) || 0);
  }

  // 指标卡环形进度（design-system ds.progress.circle）：与线形进度同阈值变色
  let memRing = null;
  function ensureRing() {
    if (memRing) return true;
    const slot = $('memUseRingSlot');
    if (!slot || !window.ds?.progress) return false; // ds.js 未加载时优雅降级为无线环
    memRing = window.ds.progress.circle({ size: 48, stroke: 5, label: '物理内存使用率' });
    slot.appendChild(memRing.el);
    return true;
  }
  function setRingValue(load) {
    const p = Math.max(0, Math.min(100, Number(load) || 0));
    const color = p >= 90 ? '#DC2626' : p >= 70 ? '#D97706' : '';
    memRing.set(p, Math.round(p) + '%', color);
  }

  // ==================== 清理区域卡片列表（点击条目弹简介） ====================
  // v3.2.0（列表项卡片样式统一）：由 xtable 四列表格改为 maint-card 同构白卡
  // （勾选 + 图标块 + 标题/风险徽章/描述 + 操作），外壳样式见 .row-card 共享类。
  // 行内展示名称 + 一句话说明（让清理项更易懂）；点击条目仍弹出详细简介弹窗（保留既有交互）。
  const MEM_REGION_ICON = '<svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M15 9H9v6h6V9zm-2 4h-2v-2h2v2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2zm-4 6H7V7h10v10z"/></svg>';
  function renderRegions() {
    const root = $('memRegionList');
    if (!root) return;
    root.innerHTML = `
      <div class="mem-region-list">
        ${REGIONS.map(r => {
          const riskBadge = r.sysUnavailable
            ? '<span class="category-risk unused">不可用</span>'
            : `<span class="category-risk ${r.risk}">${RISK_LABELS[r.risk]}</span>`;
          // N1（2026-09-14）：顽固软件治理卡片有两层 ——「立即结束进程」走专杀脚本（一次性），
          // 「阻止开机自启」走后端持久策略脚本
          const action = r.sysUnavailable
            ? '<span class="mem-region-na">系统级不可用</span>'
            : (r.kind === 'stubborn'
              ? `<button class="btn btn-secondary btn-small mem-region-clean" data-clean="${r.id}" type="button">立即结束进程</button>
                 <button class="btn btn-secondary btn-small mem-region-block" data-block="${r.id}" type="button" data-tip="把这些软件的后台服务改为手动并删除 WPS 更新任务，持久生效且不自动还原">阻止开机自启</button>`
              : `<button class="btn btn-secondary btn-small mem-region-clean" data-clean="${r.id}" type="button">清理该项</button>`);
          return `
          <div class="mem-region-row row-card ${r.sysUnavailable ? 'mem-region-disabled' : ''}" data-id="${r.id}" data-tip="点击查看该区域的详细简介">
            <label class="mem-check" data-tip="勾选后可清理该区域">
              <input type="checkbox" data-check="${r.id}" ${r.sysUnavailable ? 'disabled' : ''} ${r.checked ? 'checked' : ''} />
              <span class="mem-check-box"><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></span>
            </label>
            <div class="mem-region-icon" aria-hidden="true">${MEM_REGION_ICON}</div>
            <div class="maint-card-body">
              <div class="mem-region-title"><span class="mem-region-name">${escapeHtml(r.name)}</span>${riskBadge}</div>
              <div class="mem-region-desc">${escapeHtml(r.desc)}</div>
            </div>
            <div class="row-card-actions">${action}</div>
          </div>`;
        }).join('')}
      </div>`;

    // 勾选状态（跳过系统级不可用项）
    root.querySelectorAll('input[data-check]').forEach(cb => {
      if (cb.disabled) return;
      cb.addEventListener('change', () => {
        const r = REGIONS.find(x => x.id === cb.dataset.check);
        if (r) r.checked = cb.checked;
        updateRegionCount();
      });
    });
    // 单项清理
    root.querySelectorAll('.mem-region-clean').forEach(btn => {
      btn.addEventListener('click', () => runClean([btn.dataset.clean]));
    });
    // N1：顽固软件治理第二层 —— 阻止开机自启（持久策略，独立确认）
    root.querySelectorAll('.mem-region-block').forEach(btn => {
      btn.addEventListener('click', () => runStubbornBlock());
    });
    // 点击条目主体（非按钮/勾选框）→ 弹窗展示详细简介（本地 + 联网 AI）
    root.querySelectorAll('.mem-region-row').forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('button, input, label')) return;
        const r = REGIONS.find(x => x.id === row.dataset.id);
        if (r) showRegionIntro(r);
      });
    });
    updateRegionCount();
  }

  function updateRegionCount() {
    const cnt = $('memRegionCount');
    if (!cnt) return;
    const usable = REGIONS.filter(r => !r.sysUnavailable);
    const na = REGIONS.length - usable.length;
    cnt.textContent = `${usable.length} 项可清理 · 已选 ${usable.filter(r => r.checked).length}${na ? ` · ${na} 项系统不可用` : ''}`;
  }

  function selectAll(checked) {
    REGIONS.forEach(r => { if (!r.sysUnavailable) r.checked = checked; });
    renderRegions();
  }

  // ==================== 区域简介弹窗（复用启动项管理交互） ====================
  // v3.2.0 弹窗统一批次：骨架改由 modal.js 工厂生成
  function showRegionIntro(region) {
    const ctrl = window.modal.create({
      id: 'memRegionIntroBackdrop',
      title: region.name,
      bodyHtml: `
        <div class="startup-intro-meta">内存清理区域 · ${escapeHtml(RISK_LABELS[region.risk])}</div>
        <div data-role="introMount"></div>`,
      footerHtml: `
        <span class="model-picker-spacer"></span>
        <button class="btn btn-primary" data-role="closeBtn" type="button">关闭</button>`
    });
    ctrl.footer.querySelector('[data-role="closeBtn"]').addEventListener('click', () => ctrl.close());

    const mount = ctrl.body.querySelector('[data-role="introMount"]');
    if (window.intro?.mountIntroPanel) {
      window.intro.mountIntroPanel({
        mount,
        scope: 'memoryclean',
        name: region.name,
        company: '内存清理',
        item: { id: region.id, name: region.name, group: '内存清理', title: region.name }
      });
    } else {
      mount.innerHTML = '<div class="empty-state"><p>简介模块未加载</p></div>';
    }
  }

  // ==================== 执行清理 ====================
  async function runClean(items) {
    const requested = items || REGIONS.filter(r => r.checked).map(r => r.id);
    const selected = REGIONS.filter(r => requested.includes(r.id));
    if (!selected.length) {
      window.app?.toast('warning', '请先勾选要清理的内存区域');
      return;
    }
    const memSel = selected.filter(r => r.kind !== 'stubborn');
    const stubbornSel = selected.filter(r => r.kind === 'stubborn');
    if (stubbornSel.length) await runStubbornKill();
    if (memSel.length) await runMemoryClean(memSel);
  }

  async function runMemoryClean(regions) {
    const list = regions.map(r => r.id);
    // 危险区域二次确认（修改列表 / 备用列表全部）
    const dangerous = regions.filter(r => r.risk === 'high');
    if (dangerous.length) {
      const ok = await window.app.confirmDanger(
        '高危内存清理确认',
        `以下区域属于高危操作，可能导致系统短暂卡顿或需要重新读取数据：\n\n` +
        dangerous.map(r => `· ${r.name}`).join('\n'),
        '仍然清理',
        '取消',
        '此操作可能影响正在运行的应用，请确认已了解风险。'
      );
      if (!ok) return;
    }
    if (!window.api?.memory) {
      window.app?.toast('warning', '预览模式不支持实际清理');
      return;
    }
    window.app?.toast('info', '正在清理内存…');
    try {
      const resp = await window.api.memory.clean(list);
      // 复核 N1（提权半闭环，2026-09-16）：服务端已拦非管理员请求并回传 needAdmin，
      // 渲染层必须给出提权入口，否则用户卡死在「需要权限」无路可走（对齐 runtimes 范式）
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('内存清理需要管理员权限才能释放系统级缓存。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新点击「开始清理」');
        return;
      }
      if (resp && resp.success && resp.data) {
        const d = resp.data;
        const okCount = (d.results || []).filter(x => x.ok).length;
        const failCount = (d.results || []).length - okCount;
        // NTSTATUS 可读化
        const statusText = st => {
          const u = (Number(st) >>> 0).toString(16).toUpperCase().padStart(8, '0');
          const map = { C0000005: '权限不足', C0000022: '访问被拒绝', C0000061: '缺少特权', C0000003: '系统不支持' };
          return map[u] || `0x${u}`;
        };
        const note = (d.results || []).filter(x => !x.ok)
          .map(x => `${x.name}（${statusText(x.status)}）`).join('、');
        const freed = Number(d.freed) || 0;
        window.app?.toast('success', `内存清理完成：释放 ${fmtBytes(freed)}${okCount ? `（成功 ${okCount} 项）` : ''}${failCount ? `，${failCount} 项失败${note ? '：' + note : ''}` : ''}`);
        window.app?.log('info', `内存清理：释放 ${fmtBytes(freed)}，成功 ${okCount} 项，失败 ${failCount} 项`);
        await loadInfo();
        return;
      }
      throw new Error((resp && resp.message) || '清理失败');
    } catch (e) {
      window.app?.toast('error', '内存清理失败：' + e.message);
    }
  }

  // 顽固软件专杀：结束 MuMu/UU远程/抖音/剪映/WPS/微软电脑管家 后台守护进程，结果右上角 toast + 回传日志
  async function runStubbornKill() {
    if (!window.api?.memory?.stubbornKill) {
      window.app?.toast('warning', '预览模式不支持清理顽固软件');
      return;
    }
    window.app?.toast('info', '正在专杀顽固软件后台进程…');
    try {
      const resp = await window.api.memory.stubbornKill();
      // 复核 N1：提权半闭环收口（同 memory:clean）
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('顽固软件专杀需要管理员权限才能结束受保护的后台进程。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新点击「一键专杀」');
        return;
      }
      if (resp && resp.success && resp.data) {
        const d = resp.data;
        const killed = Number(d.killed) || 0;
        const failed = Number(d.failed) || 0;
        const leftover = Array.isArray(d.leftover) ? d.leftover : [];
        window.app?.toast('success', `顽固软件专杀完成：已结束 ${killed} 个进程` + (failed ? `，${failed} 个失败` : '') + (leftover.length ? `，仍有残留 ${leftover.join('、')}` : ''));
        window.app?.log('info', `顽固软件专杀：已结束 ${killed} 个进程，失败 ${failed} 个，剩余 ${leftover.join('、') || '无'}`);
        return;
      }
      throw new Error((resp && resp.message) || '专杀失败');
    } catch (e) {
      window.app?.toast('error', '顽固软件专杀失败：' + e.message);
    }
  }

  // N1（2026-09-14 重复点审查）：顽固软件治理第二层 —— 阻止开机自启。
  // 把 MuMu / 网易 UU 远程 / 微软电脑管家的常驻服务改为「手动」并停止，停止 WPS 云文档服务，
  // 删除 WPS 更新计划任务并关闭其自动升级。属持久策略、不提供自动还原，执行前二次确认。
  async function runStubbornBlock() {
    if (!window.api?.memory?.stubbornBlock) {
      window.app?.toast('warning', '预览模式不支持该操作');
      return;
    }
    const ok = await window.app.confirmDanger(
      '阻止顽固软件开机自启',
      '将把这些软件的后台服务启动类型改为「手动」并立即停止：MuMu 模拟器、网易 UU 远程、微软电脑管家。\n' +
      '同时停止 WPS 云文档服务、删除其更新计划任务并关闭自动升级。\n\n' +
      '该调整为持久化设置，不提供自动还原；相关软件需要使用时正常打开即可。',
      '仍然执行',
      '取消',
      '会修改服务启动类型并删除 WPS 更新计划任务。'
    );
    if (!ok) return;
    window.app?.toast('info', '正在阻止顽固软件开机自启…');
    try {
      const resp = await window.api.memory.stubbornBlock();
      // 复核 N1：提权半闭环收口（同 memory:clean）
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('阻止开机自启需要管理员权限才能修改服务启动类型。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新执行本操作');
        return;
      }
      if (resp && resp.success && resp.data) {
        const d = resp.data;
        const svcs = Array.isArray(d.services) ? d.services : [];
        const tasks = Array.isArray(d.tasks) ? d.tasks : [];
        const failS = Array.isArray(d.failedServices) ? d.failedServices : [];
        const failT = Array.isArray(d.failedTasks) ? d.failedTasks : [];
        const summary = `已处理 ${svcs.length} 个服务` + (tasks.length ? `，删除 ${tasks.length} 个更新任务` : '');
        if (failS.length || failT.length) {
          // M-1（2026-09-15）：部分失败如实告知，不吞
          window.app?.toast('warning', summary + `，但 ${failS.length + failT.length} 项失败：` +
            [...failS, ...failT].join('、'));
          window.app?.log('warn', `顽固软件自启阻断部分失败，服务失败 ${failS.join('、') || '无'}；任务失败 ${failT.join('、') || '无'}`);
        } else {
          window.app?.toast('success', summary + (svcs.length ? `：${svcs.join('、')}` : ''));
        }
        window.app?.log('info', `顽固软件自启阻断：服务 ${svcs.join('、') || '无'}；任务 ${tasks.join('、') || '无'}`);
        return;
      }
      throw new Error((resp && resp.message) || '执行失败');
    } catch (e) {
      window.app?.toast('error', '阻止开机自启失败：' + e.message);
    }
  }

  // ==================== 打开「应用进程管理」独立窗口 ====================
  async function openProcessManager() {
    try {
      if (window.api?.processManager?.openWindow) {
        const resp = await window.api.processManager.openWindow();
        if (resp && resp.success) return;
      }
      window.app?.toast('warning', '进程管理窗口暂不可用');
    } catch (e) {
      window.app?.toast('error', '打开进程管理窗口失败：' + e.message);
    }
  }

  // ==================== 初始化 ====================
  function init() {
    $('btnMemRefresh')?.addEventListener('click', () => { loadInfo(); });
    $('btnMemProcesses')?.addEventListener('click', () => { openProcessManager(); });
    $('btnMemClean')?.addEventListener('click', () => { runClean(); });
    $('btnMemSelectAll')?.addEventListener('click', () => selectAll(true));
    $('btnMemSelectNone')?.addEventListener('click', () => selectAll(false));
    $('btnOpenProcessManager')?.addEventListener('click', () => { openProcessManager(); });
    // 进程管理窗口结束进程后，实时更新卡片中间的回显区
    window.api?.processManager?.onUpdate?.((data) => {
      updateProcessEntry(data);
    });
    $('btnMemAiIntro')?.addEventListener('click', () => {
      if (window.modelpicker && typeof window.modelpicker.open === 'function') {
        window.modelpicker.open('memoryclean');
      } else {
        window.app?.toast('warning', '模型选择暂不可用，请稍后重试');
      }
    });
    applyLayout();
    renderRegions();
    loadInfo();
    loadProcessSummary();
  }

  // 读取进程管理窗口打开前的最新进程数，作为卡片初始回显
  async function loadProcessSummary() {
    try {
      if (window.api?.memory?.processes) {
        const resp = await window.api.memory.processes();
        if (resp && resp.success && Array.isArray(resp.processes)) {
          updateProcessEntry({ totalCount: resp.processes.length });
        }
      }
    } catch (_) { /* 静默，保持初始占位文案 */ }
  }

  // 更新「运行中的进程」一行式卡片中间内容区
  function updateProcessEntry(data) {
    const summary = document.querySelector('.process-entry-summary');
    if (!summary) return;
    const total = data && typeof data.totalCount === 'number' ? data.totalCount : null;
    if (total === null) {
      summary.textContent = '尚未管理进程 · 点击「去管理」打开管理窗口';
      summary.className = 'process-entry-summary';
      return;
    }
    summary.textContent = `当前共 ${total} 个运行中的进程 · 点击「去管理」查看详情`;
    summary.className = 'process-entry-summary ok';
  }

  window.memoryclean = { init, loadInfo };
})();
