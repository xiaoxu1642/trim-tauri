// peripheral.js - 外设优化（应用内弹窗）
// 两组注册表调优：Win32PrioritySeparation / MouseDataQueueSize（均为卡片单选）。
// 键盘队列深度与端口路由已收编进「优化中心」的 tf_keyboard 项（0.6.6 起本模块不再提供）。
// 卡片单选 → 「应用到注册表」写入；「恢复默认」写回 Windows 默认值。
//
// 形态：走主窗 index.html 已有的 window.modal.create 三段式骨架（usage-backdrop >
// usage-modal）；此前的独立子窗连同自绘标题栏（子窗原生标题栏 + 自绘顶栏叠加出的
// 一条黑带）一并退役。
//
// 加载方式：随 optimizer 页按需注入（app.js 的 PAGE_SCRIPTS），注入时 DOMContentLoaded
// 早已发生 —— 故不在顶层注册任何启动钩子，全部初始化收在 open() 里做。
(function () {
  'use strict';

  // ==================== 调优项定义 ====================
  const GROUPS = {
    win32: {
      regName: 'Win32PrioritySeparation',
      recommended: 38,
      defaultValue: 2,
      options: [
        { value: 26, desc: '长时间片+固定调度：上下文切换最少、整体最平滑，后台任务更稳' },
        { value: 36, desc: '短时间片+后台等量：输入延迟最低，但后台无优待' },
        { value: 38, desc: '短时间片+前台3倍时间片：Windows 官方「程序」方案，均衡推荐' },
        { value: 40, desc: '短时间片+前后台等量：公平分配，无前台提升' }
      ]
    },
    mouse: {
      regName: 'MouseDataQueueSize',
      recommended: 18,
      defaultValue: 100,
      options: [
        { value: 16, desc: '最小缓冲：延迟最低，高速移动时可能丢事件' },
        { value: 18, desc: '小缓冲：延迟低且移动更稳，均衡之选' },
        { value: 20, desc: '中等缓冲：移动更稳，延迟略升' },
        { value: 22, desc: '较大缓冲：最不易丢事件，延迟相对最高' }
      ]
    }
  };

  // 「数值解释」子弹窗的内容：每组一段，讲清这个数在系统里到底控制什么。
  // 为什么要有它（用户 2026-10-03 提的）：这些是十进制魔法数，光看「越小延迟越低」
  // 用户没法判断自己机器该选哪个，也不敢改。给出**它在系统里的作用 + 改动的代价**，
  // 才算把选择权真正交给用户。
  const EXPLAIN = {
    win32: {
      title: 'Win32PrioritySeparation（处理器调度）',
      intro: '一个十进制数，内部按十六进制拆成两位：低两位决定时间片长短，高两位决定前台程序能拿到多少倍的时间片。',
      rows: [
        ['26', '0x1A：长时间片（8 个时钟）+ 固定优先级调度。上下文切换最少，后台任务最稳，但前台响应提升有限。'],
        ['36', '0x24：短时间片（1 个）+ 前后台等量。输入延迟最低，代价是后台任务完全没有优待。'],
        ['38', '0x26：短时间片 + 前台拿 3 倍时间片。Windows「程序」电源方案用的就是它，均衡之选。'],
        ['40', '0x28：短时间片 + 前后台各 2 倍。仍然公平分配，没有前台偏向。'],
        ['2（出厂）', 'Hex 0x02：长/短时间片 + 固定调度，Windows 默认值，不做前台偏向。']
      ],
      caveat: '这一项只影响 CPU 调度公平性，不改变任何硬件开关。改成 36 在后台跑编译/渲染任务时，前台会明显更跟手，反之则相反。'
    },
    mouse: {
      title: 'MouseDataQueueSize（鼠标移动事件缓冲深度）',
      intro: '鼠标驱动在把移动/点击事件交给系统前，先在驱动内部排队。这个数就是队列能排多少个事件。',
      rows: [
        ['16', '最小缓冲。延迟最低，高速大幅甩动鼠标时可能丢事件（表现为指针「跟不上」）。'],
        ['18', '小缓冲。延迟低且移动较稳，均衡档。'],
        ['20', '中等缓冲。移动更稳，延迟略升。'],
        ['22', '较大缓冲。最不易丢事件，延迟相对最高。'],
        ['100（出厂）', 'Windows 默认缓冲深度。几乎不丢事件，排队延迟也最高。']
      ],
      caveat: '如果你用鼠标打游戏且觉得「甩动时指针发飘」，才值得改小；办公操作用 100 完全够。改完**必须重启**。'
    }
  };

  /** 一次「应用推荐设置」要写入的各组档位。 */
  const RECOMMENDED = { win32: 38, mouse: 18 };

  // 弹窗骨架的静态内容（编译期常量，无注入面；卡片本体在 renderGroup 里按 ds.esc 渲染）
  const BODY_HTML = `
    <section class="peri-section">
      <div class="peri-section-head">
        <h2 class="peri-section-title">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M11 2h2v6h-2V2zm-1 6h4a4 4 0 0 1 4 4v1H6v-1a4 4 0 0 1 4-4zm-4 7h6v7h-2a4 4 0 0 1-4-4v-3zm8 0h6v3a4 4 0 0 1-4 4h-2v-7z"/></svg>
          处理器调度优化
          <button type="button" class="peri-explain-btn" data-explain="win32" data-tip="这个数在系统里控制什么">数值解释</button>
        </h2>
        <p class="peri-section-sub">按需设置 Win32PrioritySeparation 的十进制数值（处理器优先级，越大越偏向前台响应）</p>
      </div>
      <div class="peri-cards" data-group="win32"></div>
    </section>

    <section class="peri-section">
      <div class="peri-section-head">
        <h2 class="peri-section-title">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c.83 0 1.5.67 1.5 1.5v5c0 .83-.67 1.5-1.5 1.5s-1.5-.67-1.5-1.5v-5c0-.83.67-1.5 1.5-1.5z"/></svg>
          鼠标队列优化
          <button type="button" class="peri-explain-btn" data-explain="mouse" data-tip="这个数在系统里控制什么">数值解释</button>
        </h2>
        <p class="peri-section-sub">按需设置 MouseDataQueueSize 的十进制数值（驱动事件缓冲，默认 100，越小延迟越低，过小可能丢事件）</p>
      </div>
      <div class="peri-cards" data-group="mouse"></div>
    </section>

    <p class="peri-note" id="periNote">鼠标队列大小修改后需重启电脑生效；当前值以注册表实时读取为准。</p>`;

  const FOOTER_HTML = `
    <button class="btn btn-primary" id="btnPeriApply">应用到注册表</button>
    <button class="btn btn-secondary" id="btnPeriRecommended" data-tip="按推荐档位一次性预选上面两组，再点「应用到注册表」才真正写入">应用推荐设置</button>
    <button class="btn btn-secondary" id="btnPeriRestore" data-tip="导入最近一份备份，回到你修改前的注册表值">还原修改前的值</button>
    <button class="btn btn-secondary" id="btnPeriReset" data-tip="写回 Windows 出厂默认值（非你修改前的值）">恢复 Windows 默认</button>`;

  // 当前选中值（key → value；null = 未选择，应用时跳过该组）
  const selected = { win32: null, mouse: null };

  // 主弹窗与「数值解释」子弹窗的控制器句柄：关闭前一个再开新的，避免同 id 节点被
  // 直接 remove 后遗留未释放的 Esc 监听与焦点陷阱。
  let mainCtrl = null;
  let explainCtrl = null;

  function toast(type, msg) { window.app?.toast?.(type, msg); }

  // ==================== 渲染 ====================
  function renderGroup(root, key) {
    const wrap = root.querySelector(`.peri-cards[data-group="${key}"]`);
    if (!wrap) return;
    const def = GROUPS[key];
    wrap.innerHTML = def.options.map(opt => {
      const isRec = opt.value === def.recommended;
      const isSel = selected[key] === opt.value;
      // 渲染统一走 ds.esc / ds.escAttr（AGENTS §2：转义唯一真源）。
      // 数据源目前是编译期常量，但「常量就不过闸」会让下一次数据层改动带着注入面。
      const esc = window.ds.esc;
      const escA = window.ds.escAttr;
      return `
        <div class="peri-card${isSel ? ' selected' : ''}" data-group="${escA(key)}" data-value="${escA(opt.value)}" data-tip="${escA(def.regName + ' = ' + opt.value)}">
          ${isRec ? '<span class="peri-rec">推荐</span>' : ''}
          <span class="peri-radio" aria-hidden="true"></span>
          <div class="peri-value">${esc(opt.value)}</div>
          <div class="peri-regname">${esc(def.regName)}</div>
          <div class="peri-desc">${esc(opt.desc)}</div>
        </div>`;
    }).join('');
  }

  function renderAll(root) { Object.keys(GROUPS).forEach(key => renderGroup(root, key)); }

  function setNote(root, text) {
    const note = root.querySelector('#periNote');
    if (note && text) note.textContent = text;
  }

  // ==================== 当前值读取 ====================
  function applyCurrentToSelection(data) {
    // 当前值命中选项则预选；未命中（如默认值 2 / 100）则不选，应用时跳过该组
    Object.keys(GROUPS).forEach(key => {
      const cur = Number(data?.[key]);
      selected[key] = GROUPS[key].options.some(o => o.value === cur) ? cur : null;
    });
  }

  async function loadCurrent(root) {
    if (!window.api?.peripheralWindow?.query) return;
    try {
      const resp = await window.api.peripheralWindow.query();
      if (resp && resp.success) {
        applyCurrentToSelection(resp.data);
        renderAll(root);
        const d = resp.data || {};
        setNote(root, `当前注册表值：Win32PrioritySeparation = ${d.win32 ?? '未知'} · MouseDataQueueSize = ${d.mouse ?? '未知'}。鼠标队列大小修改后需重启电脑生效。`);
      }
    } catch (e) { /* 读取失败保持未选状态 */ }
  }

  // ==================== 提权 ====================
  // 主窗可调 elevate:request（AGENTS §3：提权入口只认主窗口 label），故这里直接用
  // window.app.requestElevation；提权成功会以管理员身份重启应用，本次操作不续跑。
  async function elevateFor(action) {
    if (!window.app?.requestElevation) { toast('error', `${action}需要管理员权限，请重启应用并以管理员身份运行`); return; }
    const ok = await window.app.requestElevation(`${action}需要管理员权限才能修改系统注册表。`);
    if (!ok) toast('info', '已取消提权，本次操作未执行');
  }

  // ==================== 数值解释子弹窗 ====================
  function openExplain(groupKey) {
    const data = EXPLAIN[groupKey];
    if (!data || !window.modal?.create) return;
    if (explainCtrl) { explainCtrl.close(); explainCtrl = null; }
    const esc = (t) => window.ds.esc(String(t));
    explainCtrl = window.modal.create({
      id: 'peripheralExplainModal',
      title: data.title,
      bodyHtml: `
        <p class="peri-explain-intro">${esc(data.intro)}</p>
        <dl class="peri-explain-list">
          ${data.rows.map(([k, v]) => `
            <div class="peri-explain-row">
              <dt>${esc(k)}</dt>
              <dd>${esc(v)}</dd>
            </div>`).join('')}
        </dl>
        <p class="peri-explain-caveat">${esc(data.caveat)}</p>`,
      onClose() { explainCtrl = null; }
    });
  }

  function closeExplain() {
    if (explainCtrl) { explainCtrl.close(); explainCtrl = null; }
  }

  // ==================== 交互 ====================
  function bindEvents(ctrl) {
    // 卡片单选 / 「数值解释」/ 「应用推荐设置」统一走 backdrop 事件委托
    ctrl.backdrop.addEventListener('click', (e) => {
      const explainBtn = e.target.closest('[data-explain]');
      if (explainBtn) {
        openExplain(explainBtn.dataset.explain);
        return;
      }
      const recBtn = e.target.closest('#btnPeriRecommended');
      if (recBtn) {
        Object.keys(RECOMMENDED).forEach(k => { selected[k] = RECOMMENDED[k]; });
        renderAll(ctrl.backdrop);
        toast('info', '已按推荐档位预选两组（尚未写入，点「应用到注册表」生效）');
        return;
      }
      const card = e.target.closest('.peri-card');
      if (!card) return;
      const key = card.dataset.group;
      const value = Number(card.dataset.value);
      if (!GROUPS[key]) return;
      selected[key] = value;
      renderGroup(ctrl.backdrop, key);
    });

    ctrl.footer.querySelector('#btnPeriApply')?.addEventListener('click', async (e) => {
      if (!window.api?.peripheralWindow?.apply) { toast('info', '请在 Trim 应用内使用该功能'); return; }
      const payload = {};
      Object.keys(GROUPS).forEach(key => { payload[key] = selected[key] ?? -1; });
      if (Object.keys(GROUPS).every(key => payload[key] === -1)) {
        toast('info', '请先为至少一组调优选择一个数值');
        return;
      }
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const resp = await window.api.peripheralWindow.apply(payload);
        // 后端 PE-4 门禁回传 needAdmin：主窗直接发起提权（提权成功会以管理员重启）。
        if (resp && resp.needAdmin) {
          await elevateFor('应用这些调优（写入 HKLM 注册表）');
          return;
        }
        if (resp && resp.success) {
          toast('success', '已应用到注册表' + (payload.mouse !== -1 ? '，鼠标队列大小重启电脑后生效' : ''));
          await loadCurrent(ctrl.backdrop);
        } else {
          toast('error', resp?.message || '应用失败，可能需要以管理员身份运行 Trim');
        }
      } catch (e) {
        toast('error', '应用失败：' + e.message);
      } finally {
        btn.disabled = false;
      }
    });

    // 复核 N1/PE-5（2026-09-16）：新增「还原修改前的值」——读最新一份备份 .reg 导入，
    // 与「恢复 Windows 默认」写出厂默认值是两个语义；用户在 Trim 之前的原始定制由此找回
    ctrl.footer.querySelector('#btnPeriRestore')?.addEventListener('click', async (e) => {
      if (!window.api?.peripheralWindow?.restoreBackup) { toast('info', '请在 Trim 应用内使用该功能'); return; }
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const resp = await window.api.peripheralWindow.restoreBackup();
        if (resp && resp.needAdmin) {
          await elevateFor('还原修改前的值（导入备份 .reg）');
          return;
        }
        if (resp && resp.success) {
          toast('success', '已导入最近一份备份，还原修改前的注册表值');
          await loadCurrent(ctrl.backdrop);
        } else {
          toast('warning', resp?.message || '还原失败');
        }
      } catch (e) {
        toast('error', '还原失败：' + e.message);
      } finally {
        btn.disabled = false;
      }
    });

    ctrl.footer.querySelector('#btnPeriReset')?.addEventListener('click', async (e) => {
      if (!window.api?.peripheralWindow?.apply) { toast('info', '请在 Trim 应用内使用该功能'); return; }
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const resp = await window.api.peripheralWindow.apply({
          win32: GROUPS.win32.defaultValue,
          mouse: GROUPS.mouse.defaultValue
        });
        if (resp && resp.needAdmin) {
          await elevateFor('恢复默认值（写入 HKLM 注册表）');
          return;
        }
        if (resp && resp.success) {
          // 复核 N1：如文案说明这是 Windows 出厂默认值，不是「你修改前的值」——
          // 想回到修改前的状态请用「还原修改前的值」按钮
          toast('success', '已恢复 Windows 默认值（注意：这不是你修改前的值，鼠标队列大小重启电脑后生效）');
          await loadCurrent(ctrl.backdrop);
        } else {
          toast('error', resp?.message || '恢复失败，可能需要以管理员身份运行 Trim');
        }
      } catch (e) {
        toast('error', '恢复失败：' + e.message);
      } finally {
        btn.disabled = false;
      }
    });
  }

  // ==================== 打开 ====================
  function open() {
    if (!window.modal?.create) { toast('error', '弹窗组件未就绪，请稍后重试'); return; }
    if (mainCtrl) { mainCtrl.close(); mainCtrl = null; }
    selected.win32 = null;
    selected.mouse = null;
    mainCtrl = window.modal.create({
      id: 'peripheralModal',
      title: '外设优化',
      bodyHtml: BODY_HTML,
      footerHtml: FOOTER_HTML,
      // 「数值解释」是叠在主弹窗之上的第二层弹窗，两层都注册了 document 级 Esc 监听。
      // 不拦一下，按一次 Esc 会把主弹窗一起关掉（Esc 先落到先注册的主窗处理器）。
      // 这里让主弹窗在子弹窗开着时拒绝关闭请求，Esc 只会关掉最上层那层。
      onRequestClose() { return !explainCtrl; },
      onClose() { closeExplain(); mainCtrl = null; }
    });
    renderAll(mainCtrl.backdrop);
    bindEvents(mainCtrl);
    loadCurrent(mainCtrl.backdrop);
  }

  window.peripheral = { open };
})();
