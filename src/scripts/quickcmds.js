// quickcmds.js - 快捷指令页（系统快捷入口若干条 / 8 分类）
// F4a2-L01（v7.2 C07）：头注的「64 条」与真源不符（quickcmds.rs QUICKCMDS 现算更多）
// 且写死必腐——条数以 commands/quickcmds.rs 的 QUICKCMDS 白名单与 quickcmds-data.js
// 对拍为准，本注释不再钉数字。
// 数据：quickcmds-data.js（来自 old\快捷指令 解包分析）
// 执行：通过 IPC quickcmds:run 由主进程按白名单 spawn，渲染层不接触命令原文
(function () {
  'use strict';

  let activeCat = '全部';
  let keyword = '';

  function escapeHtml(s) { return window.ds.esc(s); }
  const CMD_META = {
    'sys-cmd-admin': {
      risk: 'high',
      label: '高风险',
      desc: '请求管理员授权；在管理员命令行中的操作会影响整台电脑。',
      hint: '以管理员权限打开 CMD；请确认理解命令用途后再执行。'
    },
    'sys-powershell': {
      risk: 'medium',
      label: '需谨慎',
      desc: '可执行命令；请只在理解命令用途后使用。',
      hint: '打开 PowerShell 命令行；请确认理解输入命令的用途。'
    },
    'sys-msconfig': {
      risk: 'medium',
      label: '需谨慎',
      desc: '可修改启动与服务配置；误操作可能影响系统启动。',
      hint: '打开系统配置；误改启动或服务配置可能影响系统启动。'
    },
    'sys-regedit': {
      risk: 'high',
      label: '高风险',
      desc: '可修改注册表；误操作可能影响系统稳定性。',
      hint: '打开注册表编辑器；错误修改可能影响系统稳定性。'
    },
    'sys-envvar': {
      risk: 'medium',
      label: '需谨慎',
      desc: '影响程序查找命令与依赖；修改前请确认原有值。',
      hint: '编辑环境变量；修改前请记录原有值，避免影响程序启动。'
    },
    'hw-diskmgmt': {
      risk: 'high',
      label: '高风险',
      desc: '可调整分区和卷；误操作可能导致数据丢失。',
      hint: '打开磁盘管理；调整分区或卷前请备份重要数据。'
    },
    'sys-rstrui': {
      risk: 'high',
      label: '高风险',
      desc: '会进入恢复流程；操作前请确认已备份重要数据。',
      hint: '进入系统还原；操作前请确认已备份重要数据。'
    },
    'sys-sdclt': {
      risk: 'high',
      label: '高风险',
      desc: '会进入恢复流程；操作前请确认已备份重要数据。',
      hint: '进入备份与还原；操作前请确认重要数据已备份。'
    }
  };

  const NAME_OVERRIDES = {
    'sys-sysdm': '系统属性（系统信息与高级设置）',
    'sys-winupdate': 'Windows 更新（检查更新与更新历史）',
    'hw-devmgmt': '设备管理器（查看和管理硬件设备）'
  };

  function cardMeta(item) {
    const meta = CMD_META[item.id];
    return meta || null;
  }

  function displayName(item) {
    return NAME_OVERRIDES[item.id] || item.name;
  }

  // 分类图标（卡片左侧色块统一走 .qc-icon 的 token 底色）
  // 审查 M20：原先每项还带 `color`（8 个离表 hex，全仓无人读）与 `grad`（8 条
  // linear-gradient，注进内联 style）—— 撞 AGENTS §2「禁彩色渐变」「只用既有 token」，
  // 故只留图标路径，配色回到 main.css 的 --accent-soft/--accent。
  const CAT_META = {
    '系统工具':     { icon: '<path d="M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4z"/>' },
    '硬件与设备':   { icon: '<path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7v2H8v2h8v-2h-2v-2h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H3V4h18v12z"/>' },
    '服务与进程':   { icon: '<path d="M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z"/>' },
    '网络':         { icon: '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>' },
    '程序和功能':   { icon: '<path d="M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z"/>' },
    '辅助工具':     { icon: '<path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14h-4v-2h4v2zm0-4h-4v-2h4v2zm0-4h-4V7h4v2z"/>' },
    '维护与诊断':   { icon: '<path d="M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4zM6.5 11.5a3 3 0 1 1 0-6 3 3 0 0 1 0 6z"/>' },
    '休眠唤醒排查': { icon: '<path d="M13 3h-2v10h2V3zm4.83 2.17l-1.42 1.42A6.99 6.99 0 0 1 19 12c0 3.87-3.13 7-7 7s-7-3.13-7-7c0-1.93.78-3.68 2.02-4.94L5.6 5.64A8.96 8.96 0 0 0 3 12a9 9 0 0 0 18 0c0-2.63-1.13-5-2.83-6.66l-1.34.83z"/>' }
  };

  function catIcon(cat) {
    const meta = CAT_META[cat] || CAT_META['系统工具'];
    return `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">${meta.icon}</svg>`;
  }

  function filtered() {
    const data = window.QUICKCMDS_DATA || {};
    const all = data.CMDS || [];
    const kw = keyword.trim().toLowerCase();
    return all.filter(c => {
      if (activeCat !== '全部' && c.cat !== activeCat) return false;
      if (!kw) return true;
      return c.name.toLowerCase().includes(kw) || displayName(c).toLowerCase().includes(kw) || c.desc.toLowerCase().includes(kw) || c.cat.includes(kw);
    });
  }

  function renderTabs() {
    const el = document.getElementById('qcTabs');
    if (!el) return;
    const data = window.QUICKCMDS_DATA || {};
    const cats = ['全部', ...(data.CATEGORIES || [])];
    const all = data.CMDS || [];
    el.innerHTML = cats.map(c => {
      const n = c === '全部' ? all.length : all.filter(x => x.cat === c).length;
      return `<button class="filter-tab${c === activeCat ? ' active' : ''}" data-qcat="${escapeHtml(c)}">${escapeHtml(c)}<span class="maint-tab-count">${n}</span></button>`;
    }).join('');
    el.querySelectorAll('[data-qcat]').forEach(btn => {
      btn.addEventListener('click', () => {
        activeCat = btn.dataset.qcat;
        renderTabs();
        renderList();
      });
    });
  }

  function renderList() {
    const el = document.getElementById('qcList');
    const countEl = document.getElementById('qcCount');
    if (!el) return;
    const list = filtered();
    if (countEl) countEl.textContent = `${list.length} 项`;

    if (!list.length) {
      el.innerHTML = `<div class="empty-state">
        <div class="empty-state-title">没有匹配的快捷指令</div>
      </div>`;
      return;
    }

    el.innerHTML = list.map(c => {
      const meta = CAT_META[c.cat] || CAT_META['系统工具'];
      const cmdMeta = cardMeta(c);
      const name = displayName(c);
      const openTip = `打开「${name}」`;
      const openLabel = `${openTip}${cmdMeta ? `；${cmdMeta.hint}` : ''}`;
      return `
        <div class="qc-card" data-id="${window.ds.escAttr(c.id)}" data-tip="${window.ds.escAttr(c.cmd)}">
          <div class="qc-icon">${catIcon(c.cat)}</div>
          <div class="qc-body">
            <div class="qc-name">${escapeHtml(name)}${cmdMeta ? ` <span class="category-risk ${window.ds.escAttr(cmdMeta.risk)}" role="note" aria-label="${window.ds.escAttr(cmdMeta.label)}：${window.ds.escAttr(cmdMeta.desc)}" data-tip="${window.ds.escAttr(cmdMeta.desc)}">${escapeHtml(cmdMeta.label)}</span>` : ''}</div>
            <div class="qc-desc">${escapeHtml(c.desc)}</div>
          </div>
          <div class="qc-actions">
            <button class="btn btn-secondary btn-small" data-qcopy="${window.ds.escAttr(c.id)}" aria-label="次要操作：复制「${window.ds.escAttr(name)}」的命令" data-tip="次要操作：复制命令到剪贴板">复制</button>
            <button class="btn btn-primary btn-small" data-qrun="${window.ds.escAttr(c.id)}" aria-label="主要操作：${window.ds.escAttr(openLabel)}" data-tip="${window.ds.escAttr(openLabel)}">打开</button>
          </div>
        </div>`;
    }).join('');

    el.querySelectorAll('[data-qrun]').forEach(btn => {
      btn.addEventListener('click', () => runCmd(btn.dataset.qrun, btn));
    });
    el.querySelectorAll('[data-qcopy]').forEach(btn => {
      btn.addEventListener('click', () => copyCmd(btn.dataset.qcopy));
    });
  }

  // 在途集合按命令 id 计数：同一条命令在途时按钮置灰、重复点击直接丢弃。
  // 为什么需要：打开通道是含 runas 的 MAIN 档，双击会起两个 UAC / 两个实例。
  const inFlight = new Set();

  async function runCmd(id, btn) {
    const item = (window.QUICKCMDS_DATA?.CMDS || []).find(c => c.id === id);
    if (!item) return;
    if (!window.api?.quickCmds?.run) {
      window.app?.toast?.('warning', '浏览器预览模式不支持执行快捷指令');
      return;
    }
    if (inFlight.has(id)) return;
    inFlight.add(id);
    if (btn) btn.disabled = true;
    try {
      const resp = await window.api.quickCmds.run(id);
      if (resp?.success) {
        window.app?.toast?.('success', `已打开「${item.name}」`);
        window.logger?.write?.('info', `快捷指令: ${item.name} (${item.cmd})`);
      } else {
        window.app?.toast?.('error', resp?.message || `打开「${item.name}」失败`);
      }
    } catch (e) {
      window.app?.toast?.('error', '执行失败：' + e.message);
    } finally {
      inFlight.delete(id);
      if (btn) btn.disabled = false;
    }
  }

  async function copyCmd(id) {
    const item = (window.QUICKCMDS_DATA?.CMDS || []).find(c => c.id === id);
    if (!item) return;
    try {
      await navigator.clipboard.writeText(item.cmd);
      window.app?.toast?.('success', '命令已复制：' + item.cmd);
    } catch (e) {
      window.app?.toast?.('error', '复制失败：' + e.message);
    }
  }

  function init() {
    const search = document.getElementById('qcSearch');
    search?.addEventListener('input', () => {
      keyword = search.value || '';
      renderList();
    });
    renderTabs();
    renderList();
  }

  window.quickcmds = { init };
})();
