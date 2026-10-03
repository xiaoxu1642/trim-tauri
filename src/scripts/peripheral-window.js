// peripheral-window.js - 外设优化（更多调优项）窗口
// 四组注册表调优：Win32PrioritySeparation / KeyboardDataQueueSize / MouseDataQueueSize /
// 键盘端口路由预设（kbdclass\Parameters 的 ConnectMultiplePorts / MaximumPortsServed /
// SendOutputToAllPorts 三值成组写）。
// 卡片单选 → 「应用到注册表」写入；「恢复默认」写回 Windows 默认值。
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
    keyboard: {
      regName: 'KeyboardDataQueueSize',
      recommended: 20,
      defaultValue: 100,
      options: [
        { value: 16, desc: '最小缓冲：延迟最低，极限连击时可能丢键' },
        { value: 18, desc: '小缓冲：延迟低且连击更稳，均衡之选' },
        { value: 20, desc: '中等缓冲：连击稳、丢键风险低，推荐' },
        { value: 22, desc: '较大缓冲：最不易丢键，延迟相对最高' }
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
    },
    // 2026-10-03 新增：把用户本机那套 kbdclass 端口设置收进产品。
    // 原先只有 3 组，这三值（同父键 kbdclass\Parameters）在界面上完全不可见，
    // 用户只能自己去注册表编辑器改 —— 现在作为一档「预设」成组暴露。
    kbdports: {
      regName: 'ConnectMultiplePorts / MaximumPortsServed / SendOutputToAllPorts',
      recommended: 1,
      defaultValue: 1,
      options: [
        { value: 1, desc: '驱动默认：不合并多端口、识别 3 个、全端口广播（推荐）' },
        { value: 2, desc: '单键鼠精简：只服务 1 个端口、不做全端口广播' },
        { value: 3, desc: '多设备扩展：合并多端口、识别 6 个端口' }
      ]
    }
  };

  // 「数值解释」面板的内容：每组一段，讲清这个数在系统里到底控制什么。
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
    keyboard: {
      title: 'KeyboardDataQueueSize（键盘事件缓冲深度）',
      intro: 'PS/2 与部分 USB 键盘驱动在把按键事件交给系统前，先在驱动内部排队。这个数就是队列能排多少个事件。',
      rows: [
        ['16', '最小缓冲。延迟最低，但极限连击（快速输入、长时间按住某键）时可能丢键。'],
        ['18', '小缓冲。延迟低且连击较稳，均衡档。'],
        ['20', '中等缓冲。丢键风险很低，延迟略高于 18 —— 推荐档。'],
        ['22', '较大缓冲。最不易丢键，代价是最高的排队延迟。'],
        ['100（出厂）', 'Windows 默认缓冲深度。几乎不会丢键，但事件在驱动里排的时间也更长。']
      ],
      caveat: '改小缓冲只在「按键延迟明显可感」时才划算；如果你从不丢键，出厂 100 反而是最稳的。这个值**必须重启**才生效。'
    },
    mouse: {
      title: 'MouseDataQueueSize（鼠标移动事件缓冲深度）',
      intro: '与键盘同理：鼠标驱动把移动/点击事件排队后才上报，这个数决定队列深度。',
      rows: [
        ['16', '最小缓冲。延迟最低，高速大幅甩动鼠标时可能丢事件（表现为指针「跟不上」）。'],
        ['18', '小缓冲。延迟低且移动较稳，均衡档。'],
        ['20', '中等缓冲。移动更稳，延迟略升。'],
        ['22', '较大缓冲。最不易丢事件，延迟相对最高。'],
        ['100（出厂）', 'Windows 默认缓冲深度。几乎不丢事件，排队延迟也最高。']
      ],
      caveat: '如果你用鼠标打游戏且觉得「甩动时指针发飘」，才值得改小；办公操作用 100 完全够。改完**必须重启**。'
    },
    kbdports: {
      title: '键盘端口路由（kbdclass\\Parameters 三值成组）',
      intro: '这三个值共用一个注册表父键，共同决定「一次按键事件往哪些端口发、驱动同时服务几个设备」。它们互相牵连，所以 Trim 把它们做成**预设档**而不是三个独立选择框 —— 任意拼装都能得到没有意义的组合。',
      rows: [
        ['档 1（推荐 / 驱动默认）', 'ConnectMultiplePorts=0、MaximumPortsServed=3、SendOutputToAllPorts=1。不合并多端口、识别 3 个端口、事件全端口广播。这是绝大多数机器的出厂值，也是本机当前值。'],
        ['档 2（单键鼠精简）', 'ConnectMultiplePorts=0、MaximumPortsServed=1、SendOutputToAllPorts=0。只服务 1 个端口、不广播。单键盘单鼠标的桌面机可以用，多设备（外接键盘 + 笔记本自带键盘）会漏键。'],
        ['档 3（多设备扩展）', 'ConnectMultiplePorts=1、MaximumPortsServed=6、SendOutputToAllPorts=1。合并多端口、最多识别 6 个。全外设笔记本 / 带扩展坞的机型需要时才选。']
      ],
      caveat: '这三个值来自 PS/2 键盘类驱动，对纯 USB 键盘的机器基本无影响（真正生效的是笔记本自带的 PS/2 兼容层）。改错方向的形态是「同时接两台键盘时按一个键两个都响」或「只按得出一个键盘」—— 属于能立刻察觉、也能立刻改回来的类型。'
    }
  };

  /** 一次「应用推荐设置」要写入的各组档位。 */
  const RECOMMENDED = { win32: 38, keyboard: 20, mouse: 18, kbdports: 1 };

  // 当前选中值（key → value；null = 未选择，应用时跳过该组）
  const selected = { win32: null, keyboard: null, mouse: null, kbdports: null };

  // 审查 PE-1（2026-09-15）：独立窗口未加载 app.js/modal.js（见 peripheral-window.html 脚本清单），
  // 原实现 window.app?.toast 与 window.modal?.toast 两条分支都不可能命中，且 window.modal 本无 toast 方法
  // → 8 处调用全部静默，失败路径（未提权写 HKLM）与输入校验守卫完全没有反馈。
  // NEW-6（L3 2026-10-01）收敛：堆叠形态实现移入 scripts/sub-toast.js（stack 形态，
  // 宿主容器 id 统一 subToastHost），此处仅薄委托；行为与原实现一致。
  function toast(type, msg) { window.subToast?.stack(type, msg); }

  /**
   * 需要管理员权限时的统一出口（审查 M3）。
   * 本窗**不能**调 elevate:request：AGENTS.md §3 的硬红线是「提权入口只认主窗口 label」，
   * 子窗调用必被来源校验拒杀 —— 旧代码先 confirm 再提权，用户点了必然得到一条失败提示。
   * 因此这里只把用户指回主窗口，不在子窗里碰提权通道。
   */
  function guideToMainElevation(action) {
    toast('warning', `${action}需要管理员权限：请回到 Trim 主窗口点「以管理员身份运行」重启应用后再试。本次操作已取消。`);
  }

  // ==================== 渲染 ====================
  function renderGroup(key) {
    const wrap = document.querySelector(`.peri-cards[data-group="${key}"]`);
    if (!wrap) return;
    const def = GROUPS[key];
    wrap.innerHTML = def.options.map(opt => {
      const isRec = opt.value === def.recommended;
      const isSel = selected[key] === opt.value;
      return `
        <div class="peri-card${isSel ? ' selected' : ''}" data-group="${key}" data-value="${opt.value}" data-tip="${def.regName} = ${opt.value}">
          ${isRec ? '<span class="peri-rec">推荐</span>' : ''}
          <span class="peri-radio" aria-hidden="true"></span>
          <div class="peri-value">${opt.value}</div>
          <div class="peri-regname">${def.regName}</div>
          <div class="peri-desc">${opt.desc}</div>
        </div>`;
    }).join('');
  }

  function renderAll() { Object.keys(GROUPS).forEach(renderGroup); }

  function setNote(text) {
    const note = document.getElementById('periNote');
    if (note && text) note.textContent = text;
  }

  // ==================== 当前值读取 ====================
  function applyCurrentToSelection(data) {
    // 标量三组：当前值命中选项则预选；未命中（如默认值 2 / 100）则不选，应用时跳过该组
    Object.keys(GROUPS).forEach(key => {
      if (key === 'kbdports') return;   // 端口组是三值组合，单独反推
      const cur = Number(data?.[key]);
      selected[key] = GROUPS[key].options.some(o => o.value === cur) ? cur : null;
    });
    selected.kbdports = matchPortPreset(data);
  }

  /** 三个端口值反推成预设档位；三值不匹配任何档位时返回 null（界面不预选）。 */
  function matchPortPreset(d) {
    const t = [
      Number(d?.kbdConnectMultiple),
      Number(d?.kbdMaxPorts),
      Number(d?.kbdSendAll)
    ];
    if (t.some(v => !Number.isInteger(v))) return null;
    // 与 native 侧 KBD_PORT_PRESETS 同序同值（1 / 2 / 3）
    const table = [[0, 3, 1], [0, 1, 0], [1, 6, 1]];
    for (let i = 0; i < table.length; i++) {
      if (table[i][0] === t[0] && table[i][1] === t[1] && table[i][2] === t[2]) return i + 1;
    }
    return null;
  }

  async function loadCurrent() {
    if (!window.api?.peripheralWindow?.query) return;
    try {
      const resp = await window.api.peripheralWindow.query();
      if (resp && resp.success) {
        applyCurrentToSelection(resp.data);
        renderAll();
        const d = resp.data || {};
        setNote(`当前注册表值：Win32PrioritySeparation = ${d.win32 ?? '未知'} · KeyboardDataQueueSize = ${d.keyboard ?? '未知'} · MouseDataQueueSize = ${d.mouse ?? '未知'} · 键盘端口 = ${selected.kbdports == null ? '非预设组合' : `档 ${selected.kbdports}`}。键盘 / 鼠标队列大小与端口路由修改后需重启电脑生效。`);
      }
    } catch (e) { /* 读取失败保持未选状态 */ }
  }

  // ==================== 交互 ====================
  function bindEvents() {
    // 卡片单选（事件委托）
    document.querySelector('.peri-body').addEventListener('click', (e) => {
      // 「数值解释」与「应用推荐设置」是独立按钮，点了不能顺带选卡片
      const explainBtn = e.target.closest('[data-explain]');
      if (explainBtn) {
        e.stopPropagation();
        openExplain(explainBtn.dataset.explain);
        return;
      }
      const recBtn = e.target.closest('#btnPeriRecommended');
      if (recBtn) {
        e.stopPropagation();
        Object.keys(RECOMMENDED).forEach(k => { selected[k] = RECOMMENDED[k]; });
        renderAll();
        toast('info', '已按推荐档位预选四组（尚未写入，点「应用到注册表」生效）');
        return;
      }
      const card = e.target.closest('.peri-card');
      if (!card) return;
      const key = card.dataset.group;
      const value = Number(card.dataset.value);
      if (!GROUPS[key]) return;
      selected[key] = value;
      renderGroup(key);
    });

    document.getElementById('btnPeriBack')?.addEventListener('click', close);
    document.getElementById('btnPeriClose')?.addEventListener('click', close);
    document.getElementById('btnPeriExplainClose')?.addEventListener('click', closeExplain);
    // 解释面板点遮罩关闭：点击目标必须**就是**遮罩本身，点面板内部不关
    document.getElementById('periExplain')?.addEventListener('click', (e) => {
      if (e.target === e.currentTarget) closeExplain();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeExplain();
    });

    document.getElementById('btnPeriApply')?.addEventListener('click', async () => {
      if (!window.api?.peripheralWindow?.apply) { toast('info', '请在 Trim 应用内使用该功能'); return; }
      const payload = {};
      Object.keys(GROUPS).forEach(key => { payload[key] = selected[key] ?? -1; });
      if (Object.keys(GROUPS).every(key => payload[key] === -1)) {
        toast('info', '请先为至少一组调优选择一个数值');
        return;
      }
      const btn = document.getElementById('btnPeriApply');
      btn.disabled = true;
      try {
        const resp = await window.api.peripheralWindow.apply(payload);
        // 复核 N3（提权半闭环，2026-09-16）：服务端 PE-4 门禁回传 needAdmin。
        // 审查 M3：本窗**不得**直接调 elevate:request —— AGENTS.md §3 是硬红线
        // 「提权入口只认主窗口 label」，子窗调用必被来源校验拒杀（此前正是因此死路一条：
        // 界面引导用户点提权，点了必然失败）。提权请回主窗口做，这里只负责把话说明白。
        if (resp && resp.needAdmin) {
          guideToMainElevation('应用这些调优（写入 HKLM 注册表）');
          return;
        }
        if (resp && resp.success) {
          toast('success', '已应用到注册表' + (payload.keyboard !== -1 || payload.mouse !== -1 ? '，键鼠队列大小重启电脑后生效' : ''));
          await loadCurrent();
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
    document.getElementById('btnPeriRestore')?.addEventListener('click', async () => {
      if (!window.api?.peripheralWindow?.restoreBackup) { toast('info', '请在 Trim 应用内使用该功能'); return; }
      const btn = document.getElementById('btnPeriRestore');
      btn.disabled = true;
      try {
        const resp = await window.api.peripheralWindow.restoreBackup();
        if (resp && resp.needAdmin) {
          guideToMainElevation('还原修改前的值（导入备份 .reg）');
          return;
        }
        if (resp && resp.success) {
          toast('success', '已导入最近一份备份，还原修改前的注册表值');
          await loadCurrent();
        } else {
          toast('warning', resp?.message || '还原失败');
        }
      } catch (e) {
        toast('error', '还原失败：' + e.message);
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById('btnPeriReset')?.addEventListener('click', async () => {
      if (!window.api?.peripheralWindow?.apply) { toast('info', '请在 Trim 应用内使用该功能'); return; }
      const btn = document.getElementById('btnPeriReset');
      btn.disabled = true;
      try {
        const resp = await window.api.peripheralWindow.apply({
          win32: GROUPS.win32.defaultValue,
          keyboard: GROUPS.keyboard.defaultValue,
          mouse: GROUPS.mouse.defaultValue,
          // 端口组出厂值 = 驱动默认档（1）。不写这一项会留下一台「只清了队列深度、
          // 端口路由还停在上一档」的机器，而回执却报「已恢复 Windows 默认」。
          kbdports: GROUPS.kbdports.defaultValue
        });
        // 复核 N3：提权半闭环收口（同「应用到注册表」）
        if (resp && resp.needAdmin) {
          guideToMainElevation('恢复默认值（写入 HKLM 注册表）');
          return;
        }
        if (resp && resp.success) {
          // 复核 N1：如文案说明这是 Windows 出厂默认值，不是「你修改前的值」——
          // 想回到修改前的状态请用「还原修改前的值」按钮
          toast('success', '已恢复 Windows 默认值（注意：这不是你修改前的值，键鼠队列大小重启电脑后生效）');
          await loadCurrent();
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

  function close() {
    // 审查 v2-M22（v1 L13 未修）：关窗是浮动 Promise，子窗此前零兜底 —— 失败即「点了没反应」。
    if (window.api?.peripheralWindow?.closeWindow) {
      window.api.peripheralWindow.closeWindow().catch((e) => toast('error', '关闭窗口失败：' + ((e && e.message) || e)));
    } else {
      window.close();
    }
  }

  // ==================== 数值解释面板 ====================
  //
  // 为什么是自绘而不是 modal.js：外设子窗**不加载** modal.js（见 peripheral-window.html
  // 脚本清单，子窗只挂 ds.js 做转义），而这些子窗刻意不引 app.js 那套大依赖。
  // 这里就地起一个 `hidden` 面板，全部文本走 window.ds.esc（AGENTS §2 硬红线）。
  //
  // 卡片声明了 aria-modal="true"（审查 M-10），模态行为由 ds.focusTrap 兑现：
  // Tab 圈闭在卡片内、关闭时焦点归还触发按钮。trap 必须存模块级引用 —— 面板开着时
  // 再点另一组「数值解释」会二次 open，不先 release 旧 trap 会让两套 focusin/keydown
  // 并存，Tab 循环紊乱。三条关闭路径（关闭钮/遮罩点击/Esc）都收口到 closeExplain。
  let explainTrap = null;

  function openExplain(groupKey) {
    const panel = document.getElementById('periExplain');
    const body = document.getElementById('periExplainBody');
    const data = EXPLAIN[groupKey];
    if (!panel || !body || !data) return;
    if (explainTrap) { explainTrap.release(); explainTrap = null; }
    const esc = (t) => window.ds.esc(String(t));
    body.innerHTML = `
      <h3 class="peri-explain-title">${esc(data.title)}</h3>
      <p class="peri-explain-intro">${esc(data.intro)}</p>
      <dl class="peri-explain-list">
        ${data.rows.map(([k, v]) => `
          <div class="peri-explain-row">
            <dt>${esc(k)}</dt>
            <dd>${esc(v)}</dd>
          </div>`).join('')}
      </dl>
      <p class="peri-explain-caveat">${esc(data.caveat)}</p>`;
    panel.hidden = false;
    explainTrap = window.ds?.focusTrap?.(
      panel.querySelector('.peri-explain-card'),
      { initialFocus: '#btnPeriExplainClose' }
    ) || null;
  }

  function closeExplain() {
    if (explainTrap) { explainTrap.release(); explainTrap = null; }
    const panel = document.getElementById('periExplain');
    if (panel) panel.hidden = true;
  }

  function init() {
    renderAll();
    bindEvents();
    loadCurrent();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
