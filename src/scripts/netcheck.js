// netcheck.js - 网络检测（v3.0）
// 6 项只读检测：单脚本一次采集（主进程），前端逐项揭示还原「逐项扫描」观感；
// 异常项展示原因 + 证据 + 修复建议；带修复动作的项提供「一键修复」
// （白名单动作 id → 主进程固定命令，红色二次确认，需管理员时走 UAC 提权握手）。
(function () {
  'use strict';

  // 检测项元数据（名称/一句话说明），id 与 netcheck-scripts.js 的输出一一对应
  const ITEM_META = {
    adapter: { name: '网络硬件配置', desc: '网卡是否存在、是否被禁用' },
    ipconfig: { name: '网络连接配置', desc: '活动网卡的有效 IPv4 与默认网关' },
    dhcp: { name: 'DHCP 服务', desc: 'Dhcp 服务运行状态与启动类型' },
    dns: { name: 'DNS 服务', desc: 'DNS Client 服务与网卡配置的 DNS 服务器' },
    proxy: { name: 'Web 代理设置', desc: '用户代理与系统代理，识别残留代理' },
    connectivity: { name: '连通性', desc: '网关、公网 DNS 解析与 HTTPS 探测' }
  };

  // 联动「系统维护」修复组（我的电脑修复）：连通性/DNS 问题的深度修复入口
  // NT-5（2026-09-15）：单一来源收敛在此（PS 侧同名单死代码已删），补回 hint 用于逐项提示
  const MAINTENANCE_LINKS = [
    { id: 'dns', label: '刷新 DNS 缓存', hint: '网页打不开/解析异常时先试' },
    { id: 'netstack', label: '重置网络栈 (Winsock/IP)', hint: '多项异常并存时的兜底重置，需重连网络' }
  ];

  const BADGE_TEXT = { pending: '等待', scanning: '扫描中', ok: '正常', warn: '警告', fail: '异常', unknown: '未验证' };
  const BADGE_CLASS = { pending: 'pending', scanning: 'scanning', ok: 'ok', warn: 'warn', fail: 'fail', unknown: 'warn' };

  const states = {};      // itemId -> { status, evidence, detail, repair }
  let nicProps = null;    // v3.7.0：网卡高级属性只读快照（独立于 6 项诊断状态）
  let collecting = false;
  let initialized = false;

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function toast(type, message, duration) {
    window.app?.toast?.(type, message, duration);
  }

  function renderAll() {
    const box = document.getElementById('netcheckList');
    if (!box) return;
    const rows = Object.keys(ITEM_META).map(id => {
      const meta = ITEM_META[id];
      const st = states[id] || { status: 'pending' };
      const cls = BADGE_CLASS[st.status] || 'pending';
      const showEvidence = st.evidence && st.evidence.length;
      let evidenceHtml = '';
      if (showEvidence) {
        evidenceHtml = '<div class="netcheck-evidence">' +
          st.evidence.map(e => '<span class="netcheck-evidence-line">' + escapeHtml(e) + '</span>').join('') +
          '</div>';
      }
      let detailHtml = '';
      if (st.detail) {
        detailHtml = '<div class="netcheck-detail">' + escapeHtml(st.detail) + '</div>';
      }
      let repairHtml = '';
      if (st.status === 'warn' || st.status === 'fail') {
        // NT-2（2026-09-15）：proxy 可能同时需要多个修复（残留用户代理 + WinHTTP），
        // 支持 repairs 数组渲染多个按钮；无数组时退化为单个 repair。
        const repairs = (Array.isArray(st.repairs) && st.repairs.length)
          ? st.repairs
          : (st.repair && st.repair.id ? [st.repair] : []);
        if (repairs.length) {
          const single = repairs.length === 1;
          repairHtml = '<div class="netcheck-actions">' +
            repairs.map(r => {
              const label = single ? '一键修复' : (REPAIR_BTN_LABEL[r.id] || '一键修复');
              return '<button class="btn btn-danger btn-small" data-netcheck-repair="' + escapeHtml(r.id) + '">' + escapeHtml(label) + '</button>';
            }).join('') +
            '</div>';
        }
      }
      // 联动系统维护：连通性/DNS 异常时提供深度修复入口（dns / netstack 任务）
      let linkHtml = '';
      if (id === 'connectivity' || id === 'dns') {
        if (st.status === 'warn' || st.status === 'fail') {
          linkHtml = '<div class="netcheck-actions netcheck-links">' +
            '<span class="netcheck-links-label">更多修复：</span>' +
            MAINTENANCE_LINKS.map(l =>
              '<button class="btn btn-secondary btn-small" data-netcheck-maint="' + escapeHtml(l.id) + '" data-tip="' + escapeHtml(l.label + '：' + (l.hint || '在「系统维护 → 网络连接」里执行')) + '">' + escapeHtml(l.label) + '</button>'
            ).join('') +
            '</div>';
        }
      }
      return '<div class="netcheck-item card" data-netcheck-id="' + escapeHtml(id) + '">' +
        '<div class="netcheck-head">' +
        '<div class="netcheck-copy"><strong>' + escapeHtml(meta.name) + '</strong>' +
        '<span>' + escapeHtml(meta.desc) + '</span></div>' +
        '<span class="netcheck-badge ' + cls + '">' +
        (cls === 'scanning' ? '<span class="netcheck-spinner"></span>' : '') +
        escapeHtml(BADGE_TEXT[st.status] || st.status) +
        '</span>' +
        '</div>' +
        detailHtml + evidenceHtml + repairHtml + linkHtml +
        '</div>';
    });
    box.innerHTML = rows.join('');
    box.querySelectorAll('[data-netcheck-repair]').forEach(btn => {
      btn.addEventListener('click', () => runRepair(btn.getAttribute('data-netcheck-repair')));
    });
    box.querySelectorAll('[data-netcheck-maint]').forEach(btn => {
      btn.addEventListener('click', () => runMaintenanceTask(btn.getAttribute('data-netcheck-maint')));
    });
  }

  // v3.7.0 议题六 P1：网卡高级属性只读枚举（方案 §7.5 第一阶段）
  // 只呈现真实枚举结果，不提供任何写入入口；虚拟网卡单独列出并标注不可写。
  const NIC_KIND_TEXT = { ethernet: '有线', wlan: '无线', other: '其他物理网卡' };

  function renderNicProps() {
    const box = document.getElementById('netcheckNicProps');
    if (!box) return;
    const nic = nicProps;
    if (!nic) { box.innerHTML = ''; return; }
    const phys = Array.isArray(nic.physical) ? nic.physical : [];
    const virt = Array.isArray(nic.virtual) ? nic.virtual : [];
    const valLines = [];
    for (const a of phys) {
      const head = `${escapeHtml(a.name)}（${escapeHtml(NIC_KIND_TEXT[a.kind] || '物理网卡')}）` +
        ` · ${escapeHtml(a.status || '')}` + (a.speed ? ` · ${escapeHtml(a.speed)}` : '');
      valLines.push('<span class="netcheck-evidence-line nic-prop-head">' + head + '</span>');
      const st = [];
      if (a.rss === true || a.rss === false) st.push('RSS ' + (a.rss ? '开' : '关'));
      if (a.csum) st.push('校验和卸载 ' + escapeHtml(a.csum));
      if (a.pmOff === true || a.pmOff === false) st.push('允许关闭设备节能 ' + (a.pmOff ? '是' : '否'));
      if (a.wolMagic === true || a.wolMagic === false) st.push('魔术包唤醒 ' + (a.wolMagic ? '开' : '关'));
      if (st.length) {
        valLines.push('<span class="netcheck-evidence-line nic-prop-sub">' + escapeHtml(st.join(' · ')) + '</span>');
      }
      const props = Array.isArray(a.props) ? a.props : [];
      if (!props.length) {
        valLines.push('<span class="netcheck-evidence-line nic-prop-sub">该网卡驱动未暴露可枚举高级属性</span>');
      } else {
        for (const p of props) {
          const valid = Array.isArray(p.valid) && p.valid.length ? `（可选：${p.valid.join(' / ')}）` : '';
          valLines.push('<span class="netcheck-evidence-line nic-prop-item">' +
            escapeHtml(`${p.name}：${p.value}${valid}`) + '</span>');
        }
      }
    }
    let virtHtml = '';
    if (virt.length) {
      virtHtml = '<div class="netcheck-detail">虚拟网卡（VPN / 虚拟交换机等）' + virt.length +
        ' 张：' + escapeHtml(virt.map(v => v.name).join('、')) + ' —— 第一版只展示，不开放写入。</div>';
    }
    box.innerHTML = '<div class="netcheck-item card" data-nic-readonly="1">' +
      '<div class="netcheck-head">' +
      '<div class="netcheck-copy"><strong>网卡高级属性（只读）</strong>' +
      '<span>按驱动真实枚举显示物理网卡的高级属性与 RSS / 校验卸载 / 电源管理状态，第一版不提供写入</span></div>' +
      '<span class="netcheck-badge ok">只读</span>' +
      '</div>' +
      (phys.length ? '<div class="netcheck-evidence">' + valLines.join('') + '</div>'
        : '<div class="netcheck-detail">未枚举到物理网卡（Get-NetAdapter -Physical）</div>') +
      virtHtml +
      '</div>';
  }

  function setAll(status) {
    for (const id of Object.keys(ITEM_META)) {
      states[id] = { status };
    }
  }

  async function startCollect() {
    if (collecting) return;
    if (!window.api?.netcheck?.collect) { toast('warning', '当前环境不支持网络检测'); return; }
    collecting = true;
    const btn = document.getElementById('btnNetcheckStart');
    if (btn) { btn.disabled = true; btn.textContent = '检测中…'; }
    setAll('scanning');
    nicProps = null;
    renderAll();
    renderNicProps();
    try {
      const resp = await window.api.netcheck.collect();
      const items = resp?.success && Array.isArray(resp.data?.items) ? resp.data.items : null;
      if (!items) {
        setAll('pending');
        renderAll();
        toast('error', resp?.message || '网络检测失败');
        return;
      }
      // 逐项揭示（~300ms 间隔），还原逐项扫描观感；数据其实已一次到位
      const byId = {};
      for (const it of items) byId[it.id] = it;
      const ids = Object.keys(ITEM_META);
      for (let i = 0; i < ids.length; i++) {
        states[ids[i]] = byId[ids[i]] || { status: 'unknown' };
        renderAll();
        if (i < ids.length - 1) await new Promise(r => setTimeout(r, 300));
      }
      // 网卡只读区在 6 项揭示完成后一次性呈现（不参与逐项扫描节奏）
      nicProps = resp?.data?.nicProps || null;
      renderNicProps();
      const bad = items.filter(it => it.status === 'fail').length;
      const warn = items.filter(it => it.status === 'warn').length;
      if (bad || warn) toast('warning', `检测完成：${bad} 项异常，${warn} 项警告`);
      else toast('success', '检测完成：全部正常');
    } catch (e) {
      setAll('pending');
      renderAll();
      toast('error', '网络检测异常: ' + e.message);
    } finally {
      collecting = false;
      if (btn) { btn.disabled = false; btn.textContent = '开始检测'; }
    }
  }

  // 修复动作：红色二次确认（启用网卡额外提示断网风险），管理员的动作走提权握手
  const REPAIR_CONFIRM = {
    'enable-adapter': {
      title: '网卡启用确认',
      msg: '将启用被禁用的网卡。\n\n注意：误操作可能短暂断开网络连接，请确认当前没有关键网络任务。',
      hint: ''
    },
    'start-dhcp': { title: 'DHCP 服务修复', msg: '将把 DHCP 服务设为自动启动并立即启动。', hint: '' },
    'start-dnscache': { title: 'DNS Client 服务修复', msg: '将启动 DNS Client（Dnscache）服务。', hint: '' },
    'reset-dns': { title: 'DNS 重置确认', msg: '把 DNS 服务器重置为自动获取（清除手动指定的 DNS）。\n\n若你依赖自定义 DNS（如广告过滤、内网解析），请先取消。', hint: '重置后依赖自定义 DNS 的场景将回退到运营商 DNS。' },
    'disable-user-proxy': { title: '关闭残留代理', msg: '检测到代理指向本机但无进程监听（残留代理）。将关闭用户代理设置。\n\n若这是你自配的代理且仍在使用，请取消。', hint: '' },
    'reset-winhttp': { title: 'WinHTTP 代理重置', msg: '将重置系统级（WinHTTP）代理为直连。部分系统服务的联网配置会在重启后完全生效。', hint: '' }
  };

  // NT-2（2026-09-15）：proxy 多修复槽位时，用动作专属按钮文案区分（单槽位仍显示「一键修复」）
  const REPAIR_BTN_LABEL = {
    'disable-user-proxy': '关闭残留代理',
    'reset-winhttp': '重置 WinHTTP',
  };

  async function runRepair(actionId) {
    const conf = REPAIR_CONFIRM[actionId] || { title: '修复确认', msg: '确定执行该修复动作？', hint: '' };
    const ok = await window.app.confirmDanger(
      conf.title,
      conf.msg,
      '执行修复', '取消',
      conf.hint || ''
    );
    if (!ok) return;
    const resp = await window.api.netcheck.repair(actionId);
    if (resp?.needAdmin) {
      const elevated = await window.app.requestElevation?.('该修复动作需要管理员权限，应用将以管理员身份重启。');
      if (elevated) toast('info', '提权成功后请回到本页重新执行修复');
      return;
    }
    if (resp?.success) toast('success', resp.message || '修复完成');
    else toast('error', resp?.message || '修复失败', 5000);
    // 主进程修复后已自动重跑检测并回传最新快照，直接刷新全部行
    if (Array.isArray(resp?.items)) {
      for (const it of resp.items) {
        if (it && it.id) states[it.id] = it;
      }
      renderAll();
    } else {
      startCollect();
    }
  }

  // 联动系统维护修复组：confirmDanger → maintenance.run（既有白名单通道）
  async function runMaintenanceTask(taskId) {
    const ok = await window.app.confirmDanger(
      '系统维护修复确认',
      (taskId === 'netstack'
        ? '将重置 Winsock 目录与 TCP/IP 栈并刷新 DNS，修复联网异常。\n\n会清空自定义网络筛选器，需重连网络。'
        : '将执行 ipconfig /flushdns 清空本地 DNS 解析缓存。'),
      '执行', '取消',
      ''
    );
    if (!ok) return;
    toast('info', '正在执行，请稍候…');
    const resp = await window.api.maintenance.run(taskId);
    if (resp?.success) toast('success', '维护任务执行完成');
    else toast('error', resp?.message || '维护任务执行失败', 5000);
  }

  function onEnter() {
    // 重复进入页面不自动重跑，保留上次结果；首次进入渲染等待态
    renderAll();
  }

  function init() {
    if (initialized) return;
    initialized = true;
    document.getElementById('btnNetcheckStart')?.addEventListener('click', startCollect);
    renderAll();
  }

  window.netcheck = { init, onEnter, startCollect };
})();
