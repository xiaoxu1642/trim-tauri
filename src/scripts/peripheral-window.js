// peripheral-window.js - 外设优化（更多调优项）窗口
// 三组注册表调优：Win32PrioritySeparation / KeyboardDataQueueSize / MouseDataQueueSize
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
      recommended: 18,
      defaultValue: 100,
      options: [
        { value: 16, desc: '最小缓冲：延迟最低，极限连击时可能丢键' },
        { value: 18, desc: '小缓冲：延迟低且连击更稳，均衡之选' },
        { value: 20, desc: '中等缓冲：连击更稳，延迟略升' },
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
    }
  };

  // 当前选中值（key → value；null = 未选择，应用时跳过该组）
  const selected = { win32: null, keyboard: null, mouse: null };

  // 审查 PE-1（2026-09-15）：独立窗口未加载 app.js/modal.js（见 peripheral-window.html 脚本清单），
  // 原实现 window.app?.toast 与 window.modal?.toast 两条分支都不可能命中，且 window.modal 本无 toast 方法
  // → 8 处调用全部静默，失败路径（未提权写 HKLM）与输入校验守卫完全没有反馈。
  // 照 models-window.js 范式自建窗口内 DOM 提示，复用 main.css 既有的 .toast-container / .toast 件。
  function toast(type, msg) {
    if (!msg) return;
    let host = document.getElementById('periToastHost');
    if (!host) {
      host = document.createElement('div');
      host.id = 'periToastHost';
      host.className = 'toast-container';
      document.body.appendChild(host);
    }
    const el = document.createElement('div');
    el.className = 'toast ' + (['success', 'error', 'warning', 'info'].includes(type) ? type : 'info');
    const text = document.createElement('div');
    text.className = 'toast-message';
    text.textContent = String(msg);
    el.appendChild(text);
    host.appendChild(el);
    setTimeout(() => {
      el.classList.add('removing');
      setTimeout(() => el.remove(), 300);
    }, 4000);
  }

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
    // 当前值命中选项则预选；未命中（如默认值 2 / 100）则不选，应用时跳过该组
    Object.keys(GROUPS).forEach(key => {
      const cur = Number(data?.[key]);
      selected[key] = GROUPS[key].options.some(o => o.value === cur) ? cur : null;
    });
  }

  async function loadCurrent() {
    if (!window.api?.peripheralWindow?.query) return;
    try {
      const resp = await window.api.peripheralWindow.query();
      if (resp && resp.success) {
        applyCurrentToSelection(resp.data);
        renderAll();
        const d = resp.data || {};
        setNote(`当前注册表值：Win32PrioritySeparation = ${d.win32 ?? '未知'} · KeyboardDataQueueSize = ${d.keyboard ?? '未知'} · MouseDataQueueSize = ${d.mouse ?? '未知'}。键盘 / 鼠标队列大小修改后需重启电脑生效。`);
      }
    } catch (e) { /* 读取失败保持未选状态 */ }
  }

  // ==================== 交互 ====================
  function bindEvents() {
    // 卡片单选（事件委托）
    document.querySelector('.peri-body').addEventListener('click', (e) => {
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
          mouse: GROUPS.mouse.defaultValue
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
    if (window.api?.peripheralWindow?.closeWindow) {
      window.api.peripheralWindow.closeWindow();
    } else {
      window.close();
    }
  }

  function init() {
    renderAll();
    bindEvents();
    loadCurrent();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
