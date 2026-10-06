// memoryclean.js - 内存清理模块
// 参考 Mem Reduct：按内存区域（工作集/修改列表/备用列表/低优先级备用列表/合并物理内存页）
// 勾选清理；区域条目点击弹窗查看详细简介（复用启动项管理的交互）。
// 「运行中的进程」入口精简为「去管理」按钮，详细列表在独立「应用进程管理」窗口展示
// （见 process-manager-window.js + processes.js）。
(function () {
  'use strict';

  const $ = id => document.getElementById(id);

  // 内存清理区域定义（与 memory-scripts.js 的 cleanScript 顺序保持一致）
  // 注：系统文件缓存(82)、注册表缓存(84) 后端不提供（NtSetSystemInformation 在该
  // 系统版本上被内核拒绝），曾以灰显「不可用」行展示，2026-10-06 用户裁定直接隐藏：
  // 入口不再渲染（区别于「清理失败」，不给用户点了没反应的路径）。
  // 顽固软件专杀(kind:'stubborn') 走独立脚本（memory:stubborn-kill），非内存区清理。
  const REGIONS = [
    { id: 'workingSet', name: '进程工作集', risk: 'low', checked: true,
      // v5 M-4：旧文案「逐进程收紧…系统进程与游戏自动跳过」与实现不符 ——
      // perf.rs 走的是系统级 MemoryEmptyWorkingSets(80,1)，无进程枚举、无跳过名单。
      // 给了不存在的安全保证，比不写更糟。
      desc: '系统级清空所有进程的工作集（不逐进程、无跳过名单）：页移入待机列表，物理内存并未立即归还，再次访问即刻换回' },
    { id: 'standbyPriority0', name: '低优先级待机', risk: 'low', checked: true,
      desc: '仅清理 0 优先级待机页，不影响常用缓存，安全' },
    { id: 'combine', name: '即时合并物理内存页', risk: 'medium', checked: true,
      desc: '此刻调用 NtSetSystemInformation(130 SystemCombinePhysicalMemoryInformation) 合并物理内存页去重，降低页表开销，Win10+ 可用；与「电脑优化中心 - 关闭 Windows 内存页合并（PageCombining）」不是同一机制，互不影响' },
    { id: 'modified', name: '修改页面列表', risk: 'high', checked: true,
      desc: '脏页写盘后回收，触发磁盘 I/O，可能短暂卡顿' },
    { id: 'standby', name: '待机列表', risk: 'high', checked: true,
      // v5 M-4：待机页本来就已计入「可用内存」，清它不会让可用量上升，只会让后续读取变冷。
      // 旧文案「释放量大」与本模块 freed 的口径（全系统可用内存净变化）直接矛盾。
      desc: '淘汰待机列表页（这部分本来就算作可用内存）：清完可用量几乎不变，代价是之后冷读变慢' },
    // N1（2026-09-14 重复点审查）：原「顽固软件专杀」与「电脑优化中心 - 顽固软件策略专杀」
    // 合并为同一张「顽固软件治理」卡片，分两层：勾选 /「立即结束进程」= 一次性杀进程；
    // 「阻止开机自启」= 常驻服务改手动 + 删 WPS 更新任务（持久，不提供自动还原）。
    // 审查 v2-M1：风险档位由 medium 升为 high —— 这条会按进程名批量结束系统里的
    // 目标进程（含前台），未保存的文档/渲染工程会直接丢失，标中风险会误导用户。
    { id: 'stubbornKill', name: '顽固软件治理', risk: 'high', checked: false, kind: 'stubborn',
      desc: '两层处理：①「立即结束进程」一次性结束 MuMu 模拟器 / 网易 UU 远程 / 抖音 / 剪映 / WPS 金山办公 / 微软电脑管家 的后台常驻与守护进程（含前台进程，请先保存工作）；②「阻止开机自启」把这些软件的后台服务改为手动启动（另含抖音与夸克网盘的更新服务），删除 WPS 更新与消息推送任务、抖音守护任务、夸克网盘更新任务，清理抖音托盘自启项，并关闭 WPS 自动升级（持久生效，不提供自动还原）' }
  ];

  const RISK_LABELS = { low: '低风险', medium: '中风险', high: '高风险' };

  let maximized = false;     // 窗口最大化（指标卡一行展示）

  function escapeHtml(s) { return window.ds.esc(s); }
  function escapeAttr(s) { return window.ds.escAttr(s); }
  function fmtBytes(bytes) { return window.ds.fmtBytes(bytes); } // 审查 M18：真源在 ds
  function fmtPercent(p) { return (isFinite(p) ? Math.round(p) : 0) + '%'; }
  // 审查 v2-L5：原先这里返回两条 `linear-gradient(90deg,#DC2626,#EF4444)` 之类的**字面量**
  // 并由 setBar 写进内联 style.background —— 4 个离表 hex + 2 条渐变，既不过 token 也不随
  // 主题走，直撞 AGENTS §2「禁彩色渐变 / 只用 main.css 既有 token」（v1 M20 同族残留）。
  // 改法：JS 侧只写语义档位 data-level，颜色由 main.css 的
  // `.progress-fill[data-level="warning"|"danger"]`（既有件，色值取 --warning/--danger）决定
  // —— 与「系统概览」页 setBar 完全同一口径，不再各写一套。
  // 阈值口径保持不动（≥90 危险 / ≥70 警戒；概览页是 90/75，两处历史值本就不同，不并档）。
  function setBar(el, percent) {
    if (!el) return;
    const p = Math.max(0, Math.min(100, Number(percent) || 0));
    el.style.width = p + '%';
    el.setAttribute('data-level', p >= 90 ? 'danger' : p >= 70 ? 'warning' : 'normal');
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
    // 审查 v2-L5：同上，阈值色不再写死 hex。ds.progress.circle 的 color 是直写
    // style.stroke 的 CSS 值，给 var() 即可随主题走（浅色/深色各一档）。
    const color = p >= 90 ? 'var(--danger)' : p >= 70 ? 'var(--warning)' : '';
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
          // N1（2026-09-14）：顽固软件治理卡片有两层 ——「立即结束进程」走专杀脚本（一次性），
          // 「阻止开机自启」走后端持久策略脚本
          const action = r.kind === 'stubborn'
            ? `<button class="btn btn-secondary btn-small mem-region-clean" data-clean="${r.id}" type="button">立即结束进程</button>
                 <button class="btn btn-secondary btn-small mem-region-block" data-block="${r.id}" type="button" data-tip="把这些软件的后台服务改为手动并删除更新任务，持久生效且不自动还原">阻止开机自启</button>`
            : `<button class="btn btn-secondary btn-small mem-region-clean" data-clean="${r.id}" type="button">清理该项</button>`;
          return `
          <div class="mem-region-row row-card" data-id="${r.id}" data-tip="点击查看该区域的详细简介">
            <label class="mem-check" data-tip="勾选后可清理该区域">
              <input type="checkbox" data-check="${r.id}" ${r.checked ? 'checked' : ''} />
              <span class="mem-check-box"><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></span>
            </label>
            <div class="mem-region-icon" aria-hidden="true">${MEM_REGION_ICON}</div>
            <div class="maint-card-body">
              <div class="mem-region-title"><span class="mem-region-name">${escapeHtml(r.name)}</span><span class="category-risk ${r.risk}">${RISK_LABELS[r.risk]}</span></div>
              <div class="mem-region-desc">${escapeHtml(r.desc)}</div>
            </div>
            <div class="row-card-actions">${action}</div>
          </div>`;
        }).join('')}
      </div>`;

    // 勾选状态
    root.querySelectorAll('input[data-check]').forEach(cb => {
      cb.addEventListener('change', () => {
        const r = REGIONS.find(x => x.id === cb.dataset.check);
        if (r) r.checked = cb.checked;
        updateRegionCount();
      });
    });
    // 单项清理
    root.querySelectorAll('.mem-region-clean').forEach(btn => {
      btn.addEventListener('click', () => withMemBusy(() => runClean([btn.dataset.clean])));
    });
    // N1：顽固软件治理第二层 —— 阻止开机自启（持久策略，独立确认）
    root.querySelectorAll('.mem-region-block').forEach(btn => {
      btn.addEventListener('click', () => withMemBusy(() => runStubbornBlock()));
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
    cnt.textContent = `${REGIONS.length} 项可清理 · 已选 ${REGIONS.filter(r => r.checked).length}`;
  }

  function selectAll(checked) {
    REGIONS.forEach(r => { r.checked = checked; });
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
  // v5 P2：内存页三条会改系统状态的入口（整页清理 / 单项清理 / 阻止开机自启）此前没有任何
  // 串行闸门 —— 高危确认弹窗 await 期间连点，会并发跑两遍 NtSetSystemInformation 链、
  // 并叠出两个确认弹窗。对照 sysrestore.js:140「进函数即 disabled」的既有写法。
  let memBusy = false;
  function withMemBusy(fn) {
    if (memBusy) {
      window.app?.toast('warning', '上一次操作尚未结束，请等待完成');
      return;
    }
    memBusy = true;
    Promise.resolve().then(fn).finally(() => { memBusy = false; });
  }

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
      // 部分成功：后端在 ok_count>0 时即 success=true；这里兜底——只要 data 里有 results，就逐项展示
      if (resp && resp.data && Array.isArray(resp.data.results)) {
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
        // v5 M-2：读数失败（freedMeasured=false）时不能写「释放 0 B」—— 那表达的是
        // "确实没释放"，而真实结论是"没测到"，两者对用户的下一步动作完全不同
        const freedTxt = d.freedMeasured ? fmtBytes(freed) : '未测到';
        // v5 M-3：toast 档位必须跟 resp.success 走。此前只看 data.results 存不存在，
        // 于是 5 个区域全被系统拒绝也弹 **success**「内存清理完成：释放 0 B，5 项失败」。
        const tier = resp.success ? (failCount ? 'warning' : 'success') : 'error';
        const parts = [`内存清理${resp.success ? '完成' : '未成功'}：释放 ${freedTxt}`, `成功 ${okCount} 项`];
        if (failCount) parts.push(`${failCount} 项失败${note ? '：' + note : ''}`);
        window.app?.toast(tier, parts.join('，'));
        window.app?.log(tier === 'error' ? 'warn' : 'info', parts.join('，'));
        await loadInfo();
        return;
      }
      throw new Error((resp && resp.message) || '清理失败');
    } catch (e) {
      window.app?.toast('error', '内存清理失败：' + e.message);
      window.app?.log('error', '内存清理异常: ' + e.message);
    }
  }

  // 顽固软件专杀：结束 MuMu/UU远程/抖音/剪映/WPS/微软电脑管家 后台守护进程，结果右上角 toast + 回传日志
  async function runStubbornKill() {
    if (!window.api?.memory?.stubbornKill) {
      window.app?.toast('warning', '预览模式不支持清理顽固软件');
      return;
    }
    // 审查 v2-M1：这条链路会结束前台进程（未保存的文档、渲染工程、游戏进度会丢），
    // 此前点「立即结束进程」是直接执行、无任何二次确认，与项目危险确认纪律不符。
    // 确认放在本函数内而非 runClean 里：卡片按钮与「开始清理」两条入口共用同一道闸。
    const ok = await window.app?.confirmDanger?.(
      '结束顽固软件进程',
      '将结束 MuMu 模拟器 / 网易 UU 远程 / 抖音 / 剪映 / WPS 金山办公 / 微软电脑管家 的后台常驻与守护进程。\n\n' +
      '注意：同名进程会被一并结束，可能包含你正在使用的前台窗口，未保存的文档、剪辑工程与游戏进度将丢失。\n' +
      '已保存好工作内容后再继续。',
      '仍然结束',
      '取消',
      '此操作不可撤销，请先保存所有工作内容。'
    );
    if (!ok) return;
    window.app?.toast('info', '正在专杀顽固软件后台进程…');
    try {
      const resp = await window.api.memory.stubbornKill();
      // 复核 N1：提权半闭环收口（同 memory:clean）
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('顽固软件专杀需要管理员权限才能结束受保护的后台进程。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新点击「一键专杀」');
        return;
      }
      // 回执对账（本轮附带修正）：后端 `stubborn_kill` 返回的是
      // { killed / failed / skipped / skippedDetail / leftover }，**没有 results 字段**，
      // 而这里原本判 `Array.isArray(resp.data.results)` —— 分支永远进不去，杀完了也弹
      // 「专杀失败」。改成按 data 对象判存在，逐字段读。
      if (resp && resp.data) {
        const d = resp.data;
        const killed = Number(d.killed) || 0;
        const failed = Number(d.failed) || 0;
        const skipped = Number(d.skipped) || 0;
        const leftover = Array.isArray(d.leftover) ? d.leftover : [];
        const skippedDetail = Array.isArray(d.skippedDetail) ? d.skippedDetail : [];
        const summary = `顽固软件专杀完成：已结束 ${killed} 个进程`
          + (failed ? `，${failed} 个失败` : '')
          + (leftover.length ? `，仍有残留 ${leftover.join('、')}` : '');
        // 审查 v2-M1：被路径判定跳过的进程必须被看见，不能表现为「静默成功 0 个」
        if (skipped > 0) {
          window.app?.toast('warning', `${summary}；${skipped} 个同名进程不在预期安装目录已跳过`);
          window.app?.log('warn', `顽固软件专杀跳过 ${skipped} 个同名进程：${skippedDetail.join('；')}`);
        } else {
          window.app?.toast('success', summary);
        }
        window.app?.log('info', `顽固软件专杀：已结束 ${killed} 个进程，失败 ${failed} 个，跳过 ${skipped} 个，剩余 ${leftover.join('、') || '无'}`);
        return;
      }
      throw new Error((resp && resp.message) || '专杀失败');
    } catch (e) {
      window.app?.toast('error', '顽固软件专杀失败：' + e.message);
    }
  }

  // N1（2026-09-14 重复点审查）：顽固软件治理第二层 —— 阻止开机自启。
  // 把目标软件的后台服务改为「手动」并停止（2026-10-06 扩至抖音与夸克网盘的更新服务），
  // 停止 WPS 云文档服务，删除 WPS 更新/推送任务、抖音守护任务、夸克网盘更新任务，
  // 清理抖音托盘 Run 自启项，并关闭 WPS 自动升级。属持久策略、不提供自动还原，执行前二次确认。
  async function runStubbornBlock() {
    if (!window.api?.memory?.stubbornBlock) {
      window.app?.toast('warning', '预览模式不支持该操作');
      return;
    }
    const ok = await window.app.confirmDanger(
      '阻止顽固软件开机自启',
      '将把这些软件的后台服务启动类型改为「手动」并立即停止：MuMu 模拟器、网易 UU 远程、微软电脑管家、抖音、夸克网盘。\n' +
      '同时停止 WPS 云文档服务，删除 WPS 更新与消息推送任务、抖音守护任务、夸克网盘更新任务，清理抖音托盘的启动项（保留注册表备份），并关闭 WPS 自动升级。\n\n' +
      '该调整为持久化设置，不提供自动还原；相关软件需要使用时正常打开即可。',
      '仍然执行',
      '取消',
      '会修改服务启动类型，并删除计划任务、清理启动项。'
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
      // 同 stubbornKill 的回执对账修正：后端 stubborn_block 也没有 results 字段。
      // 2026-10-06 扩链：新增 runValues（Run 自启项）一组，三组成败都要收。
      if (resp && resp.data) {
        const d = resp.data;
        const svcs = Array.isArray(d.services) ? d.services : [];
        const tasks = Array.isArray(d.tasks) ? d.tasks : [];
        const runVals = Array.isArray(d.runValues) ? d.runValues : [];
        const failS = Array.isArray(d.failedServices) ? d.failedServices : [];
        const failT = Array.isArray(d.failedTasks) ? d.failedTasks : [];
        const failR = Array.isArray(d.failedRunValues) ? d.failedRunValues : [];
        const failAll = [...failS, ...failT, ...failR];
        const summary = `已处理 ${svcs.length} 个服务`
          + (tasks.length ? `，删除 ${tasks.length} 个任务` : '')
          + (runVals.length ? `，清理 ${runVals.length} 个启动项` : '');
        if (failAll.length) {
          // M-1（2026-09-15）：部分失败如实告知，不吞
          window.app?.toast('warning', summary + `，但 ${failAll.length} 项失败：` +
            failAll.join('、'));
          window.app?.log('warn', `顽固软件自启阻断部分失败，服务失败 ${failS.join('、') || '无'}；任务失败 ${failT.join('、') || '无'}；启动项失败 ${failR.join('、') || '无'}`);
        } else {
          window.app?.toast('success', summary + (svcs.length ? `：${svcs.join('、')}` : ''));
        }
        window.app?.log('info', `顽固软件自启阻断：服务 ${svcs.join('、') || '无'}；任务 ${tasks.join('、') || '无'}；启动项 ${runVals.join('、') || '无'}`);
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
    $('btnMemClean')?.addEventListener('click', () => { withMemBusy(() => runClean()); });
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
