// syspanel.js — 电源计划读写 + 逐设置编辑 + 虚拟内存读写（P2 §3.6 RAINZ 对标；v5 P1 编辑器）
// 挂在 settings 页底部；由 app.js 的 PAGE_SCRIPTS.settings 按需注入、MODULES_NEEDING_INIT 显式调 init。
// 十三条通道都走 window.api.syspanel.*（对应 CHANNEL_MAP 十三个键）；后端一律 `guard(MAIN)`。
// 转义与字节格式化一律走 window.ds（AGENTS §2 硬红线，本地 escape 不许新增）。
(function () {
  'use strict';

  let inited = false;
  let powerLoaded = false;

  /** 最近一次列表读的快照（克隆默认名、编辑标题回查与回列表渲染都用它） */
  let lastPowerState = null;
  /** 编辑会话；null = 列表态。字段见 buildEditor */
  let editor = null;
  /** 编辑流程防重入（unlock → dump 往返期间） */
  let editorBusy = false;
  /** 提权意图暂存：app.js 交付时本模块可能还没 init，先收着等 init 消费 */
  let pendingEditIntent = null;

  function esc(t) { return window.ds.esc(t); }
  function escAttr(t) { return window.ds.escAttr(t); }

  function mountPower() { return document.getElementById('syspanelPowerBody'); }
  function mountPagefile() { return document.getElementById('syspanelPagefileBody'); }
  function powerRefreshBtn() { return document.getElementById('btnSyspanelPowerRefresh'); }
  function pwrToast(type, msg) { window.app?.toast?.(type, msg); }

  /** 设置稳定键：同源 dump 的 GUID 原样拼接，前后端只此一份键形（不派生显示名/行号）。 */
  function pwrKey(subgroupGuid, settingGuid) {
    return String(subgroupGuid || '') + '|' + String(settingGuid || '');
  }

  // ==================== 电源设置中文本地化与调优参考 ====================
  // 覆盖面（2026-10-15 本机注册表全量核对，204 条）：只有 15 条 FriendlyName/Description
  // 是英文字面量（其余都带 powrprof/usbui 等资源引用、API 已按系统语言出中文），
  // 全部集中在「存储」与「USB」两个子组——这里逐条补中文。
  // key 用 setting GUID：名字随系统语言变（英文系统上「合上盖子操作」也会变英文），不能作键。
  // rec = 调优参考（社区经验口径，非微软官方值）：desktopAmd / desktopIntel / laptopAmd / laptopIntel。
  const PWR_ZH = {
    // ---- 存储（0012ee47）----
    'd639518a-e56d-4345-8af2-b9f32fb26109': {
      name: '主 NVMe 空闲超时',
      desc: 'NVMe 设备进入「主非运行电源状态」前必须保持空闲的时长（毫秒）；0 表示不进入该省电态。',
      rec: {
        desktopAmd: { v: '0', why: '盘保持全速，消除进出省电态的唤醒延迟尖峰（游戏加载、随机读写更稳）；锐龙平台的深层链路低功耗态兼容性偶有报告，禁用可顺带规避。代价是待机功耗略升。' },
        desktopIntel: { v: '0', why: '延迟优先，理由同左；若在意盘温/功耗，保留默认值也可以。' },
        laptopAmd: { v: '保持默认', why: '续航优先；若出现与盘唤醒相关的卡顿迹象，可试 0 对比。' },
        laptopIntel: { v: '保持默认', why: '续航优先，同左。' },
      },
    },
    'd3d55efd-c1ff-424e-9dc3-441be7833010': {
      name: '次 NVMe 空闲超时',
      desc: 'NVMe 设备进入「次非运行电源状态」前，需要在主非运行电源状态中停留的时长（毫秒）。',
      rec: {
        desktopAmd: { v: '0', why: '不让盘再进入更深的省电态（空闲 → 主非运行 → 次非运行）；理由同上一条。' },
        desktopIntel: { v: '0', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '保持默认即可。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    'fc95af4d-40e7-4b6d-835a-56d131dbc80e': {
      name: '主 NVMe 电源状态切换延迟容限',
      desc: 'NVMe 设备空闲一段时间后，切换到「进出延迟之和（ENLAT+EXLAT）不超过本设定值」的最低非运行电源状态（微秒）。',
      rec: {
        desktopAmd: { v: '0', why: '只允许进入没有额外进出延迟代价的状态：省电深度与响应速度之间取响应优先。数值越大允许进越深的省电态。' },
        desktopIntel: { v: '0', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '允许系统按续航策略进入浅省电态。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    'dbc9e238-6de9-49e3-92cd-8c2b4946b472': {
      name: '次 NVMe 电源状态切换延迟容限',
      desc: 'NVMe 设备在主非运行电源状态停留一段时间后，切换到「进出延迟之和（ENLAT+EXLAT）不超过本设定值」的最低非运行电源状态（微秒）。',
      rec: {
        desktopAmd: { v: '0', why: '与上一条配套：不让盘进入更深省电态。' },
        desktopIntel: { v: '0', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '保持默认。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '0b2d69d7-a2a1-449c-9680-f91c70521c60': {
      name: 'AHCI 链路电源管理 — HIPM/DIPM',
      desc: '配置 SATA 链路的链路电源管理（LPM）状态。',
      rec: {
        desktopAmd: { v: 'Active', why: '禁用 SATA 链路省电：消除链路唤醒延迟与偶发掉盘——较老的 AMD 芯片组上 SATA 链路低功耗兼容性问题更常被报告。' },
        desktopIntel: { v: 'Active', why: '同左；Intel 平台问题相对少见，遇到 SATA 链路类卡顿再改也可以。' },
        laptopAmd: { v: '保持默认', why: '续航优先；出现掉盘/卡顿再改 Active。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    'dab60367-53fe-4fbc-825e-521d069d2456': {
      name: 'AHCI 链路电源管理 — 自适应',
      desc: '自动从 Partial 状态过渡到 Slumber 状态。',
      rec: {
        desktopAmd: { v: '禁用', why: '配合上一条统一关闭 SATA 链路省电。' },
        desktopIntel: { v: '禁用', why: '同左。' },
        laptopAmd: { v: '保持默认（启用）', why: '续航优先。' },
        laptopIntel: { v: '保持默认（启用）', why: '同左。' },
      },
    },
    '5e8c011f-01bc-4821-b947-deffa95af8d2': {
      name: '任意 NVMe 盘 · 非运行态 APST 空闲转换时间（毫秒）',
      desc: '适用于任意 NVMe 盘：处于非运行电源状态时的 APST（自主电源状态转换）空闲等待时间。',
    },
    '7f68c523-7536-4a79-b339-0ba0998f5dc4': {
      name: '任意 NVMe 盘 · 运行态 APST 空闲转换时间（毫秒）',
      desc: '适用于任意 NVMe 盘：处于运行电源状态时的 APST（自主电源状态转换）空闲等待时间。',
    },
    '54bbd65b-b333-4808-ae71-461b696bf60e': {
      name: '混合 NAND 盘 · 非运行态 APST 空闲转换时间（毫秒）',
      desc: '适用于混合 NAND 盘：处于非运行电源状态时的 APST 空闲等待时间。',
    },
    'b6c43707-23d2-46d4-bd1a-ac91685c76bb': {
      name: '混合 NAND 盘 · 运行态 APST 空闲转换时间（毫秒）',
      desc: '适用于混合 NAND 盘：处于运行电源状态时的 APST 空闲等待时间。',
    },
    '4016abef-65af-42a2-9939-45cb45e92634': {
      name: '混合 Optane 盘 · 非运行态 APST 空闲转换时间（毫秒）',
      desc: '适用于混合 Optane 盘：处于非运行电源状态时的 APST 空闲等待时间。',
    },
    'bb50ccc4-ef9f-4008-a470-e6ea6737f152': {
      name: '混合 Optane 盘 · 运行态 APST 空闲转换时间（毫秒）',
      desc: '适用于混合 Optane 盘：处于运行电源状态时的 APST 空闲等待时间。',
    },
    // ---- USB（2a737441）----
    'd4e98f31-5ffe-4ce1-be31-1b38b384c009': {
      name: 'USB 3 链路电源管理',
      desc: '指定 USB 3 链路空闲时采用的电源管理策略。',
      rec: {
        desktopAmd: { v: '关闭', why: 'USB 3 链路低功耗态（U1/U2 等）是外设偶发断连、无线接收器失联、外置硬盘掉盘的常见根因；台式没有续航压力，直接关最稳。' },
        desktopIntel: { v: '关闭', why: '同左；外设一切正常且在意省电的话，保留默认也可以。' },
        laptopAmd: { v: '保持默认', why: '续航优先；出现外设掉线再关。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '0853a681-27c8-4100-a2fd-82013e970683': {
      name: 'USB 集线器选择性挂起超时',
      desc: '该值用作所有 USB 集线器的空闲挂起超时（毫秒）。',
      rec: {
        desktopAmd: { v: '0', why: '禁用集线器空闲挂起，避免键鼠/接收器被挂起后唤醒迟滞或失联。' },
        desktopIntel: { v: '0', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '续航优先；键鼠迟滞再调。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '498c044a-201b-4631-a522-5c744ed4e678': {
      name: '对所有传输描述符设置 IOC',
      desc: '是否对全部传输描述符（TD）设置 IOC（传输完成中断）。',
    },
  };

  function pwrZh(settingGuid) {
    return PWR_ZH[String(settingGuid || '').toLowerCase()] || null;
  }

  /** 详情与提示共用的显示名：有中文条目显示「中文（英文原名）」。 */
  function pwrDisplayName(s) {
    const orig = String(s.name || s.guid);
    const zh = pwrZh(s.guid);
    return zh && zh.name ? `${zh.name}（${orig}）` : orig;
  }

  function pwrDisplayDesc(s) {
    const zh = pwrZh(s.guid);
    return String((zh && zh.desc) || s.description || '');
  }

  /** 列表项 tooltip：有中文条目给「中文名（英文）\n中文描述」，无条目维持原状（原文描述）。 */
  function pwrTipText(s) {
    const zh = pwrZh(s.guid);
    if (!zh) return String(s.description || s.name || '');
    const nm = pwrDisplayName(s);
    const desc = pwrDisplayDesc(s);
    return desc && desc !== nm ? nm + '\n' + desc : nm;
  }

  // ==================== 列表层（方案卡片与动作） ====================

  function renderPowerEmpty(msg) {
    const el = mountPower();
    if (el) el.innerHTML = `<p class="empty-state"><span>${esc(msg)}</span></p>`;
  }

  /** 列表与「新建电源计划」弹窗共用的排序：内置三档在前，其余按中文名排。 */
  function orderedPowerOptions() {
    return (lastPowerState?.options || []).slice().sort((a, b) => {
      if (!!a.known !== !!b.known) return a.known ? -1 : 1;
      return String(a.name || a.guid || '').localeCompare(String(b.name || b.guid || ''), 'zh-Hans-CN');
    });
  }

  function renderPower(state) {
    if (state) lastPowerState = state;
    const el = mountPower();
    if (!el) return;
    editor = null;
    const rf = powerRefreshBtn();
    if (rf) rf.style.display = '';
    const nw = document.getElementById('btnSyspanelPowerNew');
    if (nw) nw.style.display = '';
    const st = lastPowerState || {};
    const active = String(st.activeGuid || '').toLowerCase();
    const activeName = String(st.activeName || '');
    // 一页展示完毕、一视同仁可选（2026-10-14 用户裁定）：内置三档按固定顺序在前，
    // 自定义方案按名称排在后面。known 只决定说明文案与「重命名/删除」按钮是否出现
    // （微软三档的显示名走 KNOWN_PLANS 固定表，改名后界面名不会变，故不给入口；
    // 删除的三道闸 §9 里也点名不显示删除按钮）。
    // 新建统一走头部「新建电源计划」（2026-10-15 用户裁定）：模板在弹窗里选，
    // 卡片上不再各挂一颗「新建副本」。
    const ordered = orderedPowerOptions();
    const cards = ordered.map((o) => {
      const guid = String(o.guid || '');
      const isActive = !!active && guid.toLowerCase() === active;
      const name = String(o.name || guid);
      const known = !!o.known;
      // 说明小字只留给内置三档（2026-10-15 用户裁定）：自定义方案的统一说明
      // 「本机自定义方案（克隆或第三方注册）…」对用户没有信息量，反而挤占卡片高度。
      const tip = known ? String(o.tip || '') : '';
      const renameBtn = known ? ''
        : `<button type="button" class="btn btn-secondary btn-small" data-act="rename">重命名</button>`;
      const deleteBtn = known ? ''
        : `<button type="button" class="btn btn-secondary btn-small syspanel-pwr-act-danger" data-act="delete">删除</button>`;
      return `
        <div class="syspanel-power-tile" data-active="${isActive ? '1' : ''}" data-guid="${escAttr(guid)}" data-name="${escAttr(name)}">
          <span class="syspanel-power-tile-main">
            <span class="syspanel-power-tile-name">${esc(name)}${isActive ? ' <span class="syspanel-badge">当前</span>' : ''}</span>
            ${tip ? `<span class="syspanel-power-tile-tip" data-tip="${escAttr(tip)}">${esc(tip)}</span>` : ''}
          </span>
          <span class="syspanel-power-tile-actions">
            <button type="button" class="btn btn-secondary btn-small" data-act="apply"${isActive ? ' disabled data-tip="这已经是当前方案"' : ''}>应用</button>
            <button type="button" class="btn btn-secondary btn-small" data-act="edit">编辑</button>
            ${renameBtn}
            <button type="button" class="btn btn-secondary btn-small" data-act="export" data-tip="导出为 .powrplan 文件">导出</button>
            ${deleteBtn}
          </span>
        </div>`;
    }).join('');
    el.innerHTML = `
      <div class="syspanel-power-current">当前方案：<strong>${esc(activeName || '未知')}</strong></div>
      <div class="syspanel-power-grid">${cards}</div>
      <div class="syspanel-actions">
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPowerImport">导入方案文件…</button>
      </div>
    `;
    el.querySelector('.syspanel-power-grid')?.addEventListener('click', onPowerTileClick);
    document.getElementById('btnSyspanelPowerImport')?.addEventListener('click', onImportPower);
  }

  function onPowerTileClick(ev) {
    const btn = ev.target.closest('button[data-act]');
    if (!btn || btn.disabled) return;
    const tile = btn.closest('.syspanel-power-tile');
    const guid = tile?.dataset?.guid || '';
    const name = tile?.dataset?.name || guid;
    const act = btn.dataset.act;
    if (act === 'apply') onApplyPower(guid, name, tile);
    else if (act === 'edit') {
      // unlock + dump 真机约秒级，期间按钮必须给出反馈，否则用户以为没点上而连点
      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = '进入中…';
      Promise.resolve(enterPowerEditor(guid)).catch(() => {}).finally(() => {
        if (btn.isConnected) { btn.disabled = false; btn.textContent = orig; }
      });
    }
    else if (act === 'rename') onRenamePower(guid, name);
    else if (act === 'export') onExportPower(guid, name);
    else if (act === 'delete') onDeletePower(guid, name);
  }

  async function onApplyPower(guid, name, tile) {
    // 当前方案那颗按钮是 disabled（如实反映系统状态）；这里防御键盘/程序化触发。
    if (tile?.dataset?.active === '1') {
      pwrToast('info', '这已经是当前方案');
      return;
    }
    // 电源方案切换会立即影响功耗与温度：走 confirmWarning，不走 confirmDanger（可回切、非破坏性）
    const ok = await window.app?.confirmWarning?.(
      '切换电源方案',
      `确认切换到「${name}」？切换后系统会立刻按新方案调度 CPU 与外设电源。`,
      '应用',
      '取消',
    );
    if (!ok) return;
    try {
      const resp = await window.api.syspanel.powerPlanApply(guid);
      if (resp && resp.success) {
        renderPower(resp.data);
        pwrToast('info', '电源方案已切换并回读校验通过');
      } else {
        pwrToast('error', (resp && resp.message) || '切换失败');
        await loadPower(); // 失败后**重读**，把实际状态摆回面板（不假装成功）
      }
    } catch (e) {
      pwrToast('error', '切换异常：' + (e && e.message ? e.message : String(e)));
      await loadPower();
    }
  }

  /** 默认名：`用户自定义方案x`，x 从 1 起取第一个不与现有方案重名的号（删掉中间一个再新建也不撞）。 */
  function nextDefaultPlanName() {
    const names = new Set((lastPowerState?.options || []).map((o) => String(o.name || '')));
    let i = 1;
    while (names.has('用户自定义方案' + i)) i++;
    return '用户自定义方案' + i;
  }

  /** 名称输入弹窗（新建副本 / 重命名共用）。onSubmit 返回 true 才关弹窗，false 留着让用户改。 */
  function promptPlanName(title, initial, hint, onSubmit) {
    if (!window.modal?.create) {
      pwrToast('warning', '当前环境不支持名称输入');
      return;
    }
    const ctrl = window.modal.create({
      id: 'syspanelPwrNameModal',
      title,
      bodyHtml: `
        <p class="syspanel-pwr-modal-hint">${esc(hint)}</p>
        <input type="text" class="syspanel-pwr-input" id="syspanelPwrNameInput" value="${escAttr(initial)}" maxlength="200" />
      `,
      footerHtml: `
        <button type="button" class="btn btn-secondary" data-modal-cancel>取消</button>
        <button type="button" class="btn btn-primary" data-modal-ok>确定</button>
      `,
      width: 420,
      initialFocus: '#syspanelPwrNameInput',
    });
    const input = ctrl.body.querySelector('#syspanelPwrNameInput');
    const okBtn = ctrl.footer.querySelector('[data-modal-ok]');
    const submit = async () => {
      const val = String(input?.value || '').trim();
      if (!val) { input?.focus(); return; }
      okBtn.disabled = true;
      let ok = false;
      try { ok = !!(await onSubmit(val)); } finally {
        okBtn.disabled = false;
      }
      if (ok) ctrl.close();
    };
    ctrl.footer.querySelector('[data-modal-cancel]').addEventListener('click', () => ctrl.close());
    okBtn.addEventListener('click', submit);
    input?.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  }

  /** 头部「新建电源计划」（2026-10-15 用户裁定：入口收在卡片头部，模板在弹窗里选，
   *  不学「每卡一颗新建副本」）。对齐 Windows 原生「创建电源计划」：选模板 + 填名称。 */
  function onNewPowerPlan() {
    if (editor) { pwrToast('info', '正在编辑中，请先保存或取消'); return; }
    if (!window.api?.syspanel?.powerPlanDuplicate) {
      pwrToast('warning', '当前环境不支持新建电源计划');
      return;
    }
    const opts = orderedPowerOptions();
    if (!opts.length) { pwrToast('warning', '方案列表尚未读取完成，请稍后重试'); return; }
    const activeGuid = String(lastPowerState?.activeGuid || '').toLowerCase();
    const baseOpts = opts.map((o) => {
      const isActive = String(o.guid || '').toLowerCase() === activeGuid;
      return `<option value="${escAttr(String(o.guid || ''))}"${isActive ? ' selected' : ''}>${esc(String(o.name || o.guid))}${isActive ? '（当前）' : ''}</option>`;
    }).join('');
    if (!window.modal?.create) { pwrToast('warning', '当前环境不支持新建电源计划'); return; }
    const ctrl = window.modal.create({
      id: 'syspanelPwrNewModal',
      title: '新建电源计划',
      bodyHtml: `
        <p class="syspanel-pwr-modal-hint">新方案以所选模板为基底克隆；创建后不会自动切换为当前方案。</p>
        <label class="syspanel-pwr-modal-field" for="syspanelPwrNewBase">基于模板
          <select class="syspanel-pwr-input syspanel-pwr-modal-select" id="syspanelPwrNewBase">${baseOpts}</select>
        </label>
        <label class="syspanel-pwr-modal-field" for="syspanelPwrNewName">方案名称
          <input type="text" class="syspanel-pwr-input" id="syspanelPwrNewName" value="${escAttr(nextDefaultPlanName())}" maxlength="200" />
        </label>
      `,
      footerHtml: `
        <button type="button" class="btn btn-secondary" data-modal-cancel>取消</button>
        <button type="button" class="btn btn-primary" data-modal-ok>创建</button>
      `,
      width: 420,
      initialFocus: '#syspanelPwrNewName',
    });
    const baseSel = ctrl.body.querySelector('#syspanelPwrNewBase');
    const nameInput = ctrl.body.querySelector('#syspanelPwrNewName');
    const okBtn = ctrl.footer.querySelector('[data-modal-ok]');
    const submit = async () => {
      const baseGuid = String(baseSel?.value || '');
      const name = String(nameInput?.value || '').trim();
      if (!baseGuid || !name) { nameInput?.focus(); return; }
      okBtn.disabled = true;
      try {
        const resp = await window.api.syspanel.powerPlanDuplicate(baseGuid, name);
        if (!resp || !resp.success) {
          pwrToast('error', (resp && resp.message) || '新建失败');
          return;
        }
        renderPower(resp.data?.state);
        pwrToast('info', `已新建「${resp.data?.name || name}」`);
        ctrl.close();
      } catch (e) {
        pwrToast('error', '新建异常：' + (e && e.message ? e.message : String(e)));
      } finally {
        okBtn.disabled = false;
      }
    };
    ctrl.footer.querySelector('[data-modal-cancel]').addEventListener('click', () => ctrl.close());
    okBtn.addEventListener('click', submit);
    nameInput?.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  }

  function onRenamePower(guid, name) {
    promptPlanName('重命名电源方案', name, '新名称保存后立即生效；当前方案的名称变化不影响系统调度。', async (newName) => {
      if (newName === name) return true;
      try {
        const resp = await window.api.syspanel.powerPlanRename(guid, newName);
        if (!resp || !resp.success) {
          pwrToast('error', (resp && resp.message) || '重命名失败');
          return false;
        }
        renderPower(resp.data?.state);
        pwrToast('info', `已重命名为「${newName}」`);
        return true;
      } catch (e) {
        pwrToast('error', '重命名异常：' + (e && e.message ? e.message : String(e)));
        return false;
      }
    });
  }

  async function onExportPower(guid, name) {
    // P0 真机实测：标准权限下 powercfg /export 退出码 1 且无产物 ⇒ 导出必须发生在提权会话内。
    // isAdmin 未知（null）不预判，交给后端如实报错。
    const st = window.app?.getState?.();
    if (st && st.isAdmin === false) {
      pwrToast('warning', '导出需要管理员权限（标准权限下系统会拒绝导出）：请先点「编辑」完成提权，再回来导出。');
      return;
    }
    try {
      const resp = await window.api.syspanel.powerPlanExport(guid);
      if (!resp || !resp.success) {
        pwrToast('error', (resp && resp.message) || '导出失败');
        return;
      }
      if (resp.data?.canceled) return;
      pwrToast('info', `「${name}」已导出（${resp.data?.bytes ?? 0} 字节）`);
    } catch (e) {
      pwrToast('error', '导出异常：' + (e && e.message ? e.message : String(e)));
    }
  }

  async function onDeletePower(guid, name) {
    // 删除不可从 Trim 内恢复（系统方案无回收站语义）⇒ red 档确认；默认焦点落主按钮
    // （2026-10-03 裁定：护栏由红色按钮 +「仍然删除」文案 + 结构化警示承担）。
    const ok = await window.app?.confirmDanger?.(
      '删除电源方案',
      `即将删除「${name}」；删除后该方案的设置无法从 Trim 内恢复（需要保留可先导出为 .powrplan）。\n\n必须知道：\n`
        + '· 微软内置三档与当前正在使用的方案不可删除；\n'
        + '· 若它正被其他工具引用（如厂商性能模式），删除后那些工具可能读取失败。',
      '仍然删除',
      '取消',
      '此操作会从系统中永久移除该电源方案。',
    );
    if (!ok) return;
    try {
      const resp = await window.api.syspanel.powerPlanDelete(guid, !!ok);
      if (!resp || !resp.success) {
        pwrToast('error', (resp && resp.message) || '删除失败');
        await loadPower();
        return;
      }
      renderPower(resp.data?.state);
      pwrToast('info', `已删除「${name}」`);
    } catch (e) {
      pwrToast('error', '删除异常：' + (e && e.message ? e.message : String(e)));
      await loadPower();
    }
  }

  async function onImportPower() {
    try {
      const resp = await window.api.syspanel.powerPlanImport();
      if (!resp || !resp.success) {
        pwrToast('error', (resp && resp.message) || '导入失败');
        return;
      }
      if (resp.data?.canceled) return;
      renderPower(resp.data?.state);
      pwrToast('info', `已导入「${resp.data?.name || ''}」`);
    } catch (e) {
      pwrToast('error', '导入异常：' + (e && e.message ? e.message : String(e)));
    }
  }

  // ==================== 编辑层（unlock → dump → 编辑 → 三按钮） ====================

  /** 编辑入口（卡片「编辑」按钮与提权接回事件共用）：
   *  非管理员 → 后端写了一一次性意图，这里带 token 走 elevate.request 重启提权；
   *  已是管理员 → unlock 已返回会话，补 dump 后进编辑器。 */
  async function enterPowerEditor(guid) {
    if (editorBusy || editor) return;
    if (!window.api?.syspanel?.powerSettingsUnlock) {
      pwrToast('warning', '当前环境不支持编辑电源计划');
      return;
    }
    editorBusy = true;
    try {
      const resp = await window.api.syspanel.powerSettingsUnlock(guid);
      // unlock 部分失败（受保护设置拒绝解锁）时后端把 success 置 false 但 sessionId 仍然有效
      // ——这种不是整链失败：进编辑器、由 failed[] 如实标出不可编辑项（V10/V19 口径）。
      if (!resp || (!resp.success && !resp.data?.sessionId)) {
        pwrToast('error', (resp && resp.message) || '进入编辑失败');
        return;
      }
      const data = resp.data || {};
      if (data.needsElevation) {
        pwrToast('info', '编辑电源计划需要管理员权限，正在请求提权（UAC）…');
        const r = await window.api.elevate?.request?.(data.launchToken);
        if (r && r.success) {
          if (r.alreadyAdmin) { // 防御：unlock 判非管理员、elevate 判已是管理员不应发生
            await enterPowerEditor(guid);
            return;
          }
          pwrToast('info', '应用即将以管理员身份重启；重启后会直接进入编辑界面');
        } else {
          pwrToast('warning', (r && r.message) || '提权请求被取消，未进入编辑');
        }
        return;
      }
      const dumpResp = await window.api.syspanel.powerSettingsDump(guid);
      if (!dumpResp || !dumpResp.success) {
        // dump 失败不能把设置解锁状态半留着：按会话快照回滚属性后退出
        try { await window.api.syspanel.powerSettingsRevert(guid, data.sessionId); } catch (e2) {}
        pwrToast('error', (dumpResp && dumpResp.message) || '读取设置列表失败，已退出编辑');
        return;
      }
      buildEditor(guid, data, dumpResp.data || {});
    } catch (e) {
      pwrToast('error', '进入编辑异常：' + (e && e.message ? e.message : String(e)));
    } finally {
      editorBusy = false;
    }
  }

  function buildEditor(guid, unlockData, dump) {
    const el = mountPower();
    if (!el) return;
    const opt = (lastPowerState?.options || []).find(
      (o) => String(o.guid || '').toLowerCase() === String(guid || '').toLowerCase(),
    );
    const failedKeys = new Set(
      (unlockData.failed || []).map((f) => pwrKey(f.subgroupGuid, f.settingGuid)),
    );
    editor = {
      schemeGuid: String(guid || '').toLowerCase(),
      schemeName: String(opt?.name || guid || ''),
      sessionId: String(unlockData.sessionId || ''),
      dump,
      origin: new Map(),   // key → {ac, dc} 原始值
      changes: new Map(),  // key → {subgroupGuid, settingGuid, ac, dc}；只有净变化才在表里
      invalidKeys: new Set(), // 输入形状不合法（非整数/超 u32）的 key，不提交
      failedKeys,          // 系统拒绝解锁的设置，列表里禁用
      dcVisible: dump.platformRole === 'mobile' || dump.platformRole === 'slate',
      collapsed: new Set(), // 默认全部折叠：初始先塞全部组名，点开再删
      selectedKey: '',
      saving: false,
    };
    for (const g of dump.subgroups || []) {
      editor.collapsed.add(String(g.guid || ''));
      for (const s of g.settings || []) {
        editor.origin.set(pwrKey(s.subgroupGuid, s.guid), { ac: s.valueAc, dc: s.valueDc });
      }
    }
    // 编辑态下头部「刷新 / 新建」会整块重绘列表、丢掉会话；隐藏它们，退出编辑时恢复
    const rf = powerRefreshBtn();
    if (rf) rf.style.display = 'none';
    const nw = document.getElementById('btnSyspanelPowerNew');
    if (nw) nw.style.display = 'none';
    renderEditor();
  }

  function exitEditor() {
    editor = null;
    const rf = powerRefreshBtn();
    if (rf) rf.style.display = '';
    const nw = document.getElementById('btnSyspanelPowerNew');
    if (nw) nw.style.display = '';
  }

  function renderEditor() {
    const el = mountPower();
    if (!el || !editor) return;
    const ed = editor;
    const groupsHtml = (ed.dump.subgroups || []).map((g) => {
      const gGuid = String(g.guid || '');
      const gName = String(g.name || gGuid);
      const items = g.settings || [];
      const collapsed = ed.collapsed.has(gGuid);
      const itemsHtml = items.map((s) => {
        const key = pwrKey(s.subgroupGuid, s.guid);
        const failed = ed.failedKeys.has(key);
        const changed = ed.changes.has(key);
        const tip = failed ? '系统拒绝解锁此设置，点击查看说明' : pwrTipText(s);
        // 受保护项不用 disabled：disabled 的点击既不能选中也不给提示，等于「点了没反应」；
        // 用 is-locked 弱化视觉，点击仍可选中并在详情区看到拒绝原因。
        return `
          <button type="button" class="syspanel-pwr-item${changed ? ' is-changed' : ''}${failed ? ' is-locked' : ''}"
                  data-key="${escAttr(key)}" data-tip="${escAttr(tip)}">
            <span class="syspanel-pwr-item-name">${esc(String(s.name || s.guid))}</span>
            <span class="syspanel-pwr-item-sum">${esc(pwrValueSummary(s, key))}</span>
          </button>`;
      }).join('');
      return `
        <div class="syspanel-pwr-group" data-group="${escAttr(gGuid)}">
          <button type="button" class="syspanel-pwr-group-head" aria-expanded="${collapsed ? 'false' : 'true'}">
            <span class="syspanel-pwr-caret" aria-hidden="true">${collapsed ? '▸' : '▾'}</span>
            <span class="syspanel-pwr-group-name">${esc(gName)}</span>
            <span class="syspanel-pwr-group-meta"></span>
          </button>
          <div class="syspanel-pwr-group-items"${collapsed ? ' hidden' : ''}>${itemsHtml}</div>
        </div>`;
    }).join('');
    const failedCount = ed.failedKeys.size;
    const failNote = failedCount
      ? `<div class="syspanel-pwr-unlock-note">有 ${failedCount} 项设置被系统拒绝解锁（多为受保护的固件类设置），已标记为不可编辑。</div>`
      : '';
    el.innerHTML = `
      <div class="syspanel-pwr-editor">
        <div class="syspanel-pwr-editor-head">
          <div class="syspanel-pwr-editor-title" data-tip="${escAttr(ed.schemeGuid)}">编辑方案：<strong>${esc(ed.schemeName)}</strong></div>
          <label class="syspanel-pwr-dc-toggle" data-tip="台式机默认隐藏电池列；笔记本或需要配置电池策略时勾选">
            <input type="checkbox" id="syspanelPwrDcToggle"${ed.dcVisible ? ' checked' : ''}>
            <span>显示电池（DC）设置</span>
          </label>
        </div>
        ${failNote}
        <div class="syspanel-pwr-count" id="syspanelPwrCount" role="status"></div>
        <div class="syspanel-pwr-editor-body">
          <div class="syspanel-pwr-tree" id="syspanelPwrTree">${groupsHtml || '<p class="empty-state"><span>本方案没有枚举到可编辑的设置</span></p>'}</div>
          <div class="syspanel-pwr-detail" id="syspanelPwrDetail">
            <p class="empty-state"><span>从左侧选一项设置查看并修改取值</span></p>
          </div>
        </div>
        <div class="syspanel-pwr-editor-actions">
          <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPwrCancel">取消</button>
          <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPwrSave">确定并保存</button>
          <button type="button" class="btn btn-primary btn-small" id="btnSyspanelPwrSaveApply">保存并应用</button>
        </div>
      </div>`;
    document.getElementById('syspanelPwrTree')?.addEventListener('click', onTreeClick);
    const detailBox = document.getElementById('syspanelPwrDetail');
    // select 在 WebView2 里 input 与 change 都会来；两个都绑，applyLocalChange 幂等
    detailBox?.addEventListener('input', onDetailInput);
    detailBox?.addEventListener('change', onDetailInput);
    document.getElementById('syspanelPwrDcToggle')?.addEventListener('change', (e) => {
      if (!editor) return;
      editor.dcVisible = !!e.target.checked;
      document.querySelectorAll('.syspanel-pwr-item').forEach((node) => {
        const s = findSetting(node.dataset.key);
        const sum = node.querySelector('.syspanel-pwr-item-sum');
        if (s && sum) sum.textContent = pwrValueSummary(s, node.dataset.key);
      });
      renderDetail();
    });
    document.getElementById('btnSyspanelPwrCancel')?.addEventListener('click', editorCancel);
    document.getElementById('btnSyspanelPwrSave')?.addEventListener('click', () => editorSave(false));
    document.getElementById('btnSyspanelPwrSaveApply')?.addEventListener('click', () => editorSave(true));
    refreshGroupMeta();
    refreshCount();
  }

  function onTreeClick(ev) {
    if (!editor) return;
    const head = ev.target.closest('.syspanel-pwr-group-head');
    if (head) {
      const gNode = head.closest('.syspanel-pwr-group');
      const list = gNode?.querySelector('.syspanel-pwr-group-items');
      if (!gNode || !list) return;
      const nowCollapsed = list.hasAttribute('hidden');
      if (nowCollapsed) editor.collapsed.delete(gNode.dataset.group);
      else editor.collapsed.add(gNode.dataset.group);
      list.toggleAttribute('hidden', !nowCollapsed);
      head.setAttribute('aria-expanded', nowCollapsed ? 'true' : 'false');
      const caret = head.querySelector('.syspanel-pwr-caret');
      if (caret) caret.textContent = nowCollapsed ? '▾' : '▸';
      return;
    }
    const item = ev.target.closest('.syspanel-pwr-item');
    if (!item) return;
    // 切走时该设置的无效输入标记随详情区一起清掉（详情区重建后显示的是最后一个有效值）
    if (editor.selectedKey && editor.selectedKey !== item.dataset.key) {
      if (editor.invalidKeys.delete(editor.selectedKey)) refreshCount();
    }
    editor.selectedKey = item.dataset.key || '';
    document.querySelectorAll('.syspanel-pwr-item.is-active').forEach((n) => n.classList.remove('is-active'));
    item.classList.add('is-active');
    renderDetail();
  }

  function findSetting(key) {
    if (!editor || !key) return null;
    for (const g of editor.dump.subgroups || []) {
      for (const s of g.settings || []) {
        if (pwrKey(s.subgroupGuid, s.guid) === key) return s;
      }
    }
    return null;
  }

  /** 该项当前生效值：改动表优先，否则原始值。 */
  function currentValueOf(key, side) {
    const o = editor.origin.get(key) || {};
    const cur = editor.changes.get(key);
    if (cur) {
      const v = side === 'ac' ? cur.ac : cur.dc;
      if (v !== null && v !== undefined) return v;
    }
    return side === 'ac' ? o.ac : o.dc;
  }

  function pwrValueSummary(s, key) {
    const fmt = (v) => (v === null || v === undefined ? '—' : String(v));
    const ac = fmt(currentValueOf(key, 'ac'));
    if (editor?.dcVisible) return `${ac} / ${fmt(currentValueOf(key, 'dc'))}`;
    return ac;
  }

  function renderDetail() {
    const box = document.getElementById('syspanelPwrDetail');
    if (!box || !editor) return;
    const key = editor.selectedKey;
    const s = findSetting(key);
    if (!s) {
      box.innerHTML = '<p class="empty-state"><span>从左侧选一项设置查看并修改取值</span></p>';
      return;
    }
    const failed = editor.failedKeys.has(key);
    const dis = failed ? ' disabled' : '';
    const unit = String(s.unit || '');
    const controlHtml = (side, label) => {
      const val = currentValueOf(key, side);
      const inputId = 'syspanelPwrVal-' + side;
      let control;
      if (Array.isArray(s.possibleValues) && s.possibleValues.length) {
        // 当前值可能不在系统给出的枚举内（真机实测存在这种合法既成事实，如
        // 「合上盖子操作」当前 1 / 枚举 0,2,3,6）：补一个选中项如实显示，绝不静默落到第一项。
        const inEnum = val !== null && val !== undefined && s.possibleValues.some((v) => Number(v) === Number(val));
        const curOpt = (!inEnum && val !== null && val !== undefined)
          ? `<option value="${escAttr(String(val))}" selected>${esc(String(val))}（当前值）</option>`
          : '';
        const opts = s.possibleValues
          .map((v) => `<option value="${escAttr(String(v))}"${Number(val) === Number(v) ? ' selected' : ''}>${esc(String(v))}</option>`)
          .join('');
        control = `<select class="syspanel-pwr-input" id="${inputId}" data-side="${side}"${dis}>${curOpt}${opts}</select>`;
      } else {
        const r = s.range || {};
        const minAttr = Number.isFinite(Number(r.min)) ? ` min="${Number(r.min)}"` : '';
        const maxAttr = Number.isFinite(Number(r.max)) ? ` max="${Number(r.max)}"` : '';
        const stepAttr = Number.isFinite(Number(r.step)) && Number(r.step) > 0 ? ` step="${Number(r.step)}"` : '';
        control = `<input type="number" class="syspanel-pwr-input" id="${inputId}" data-side="${side}" value="${val === null || val === undefined ? '' : Number(val)}"${minAttr}${maxAttr}${stepAttr}${dis}>`;
      }
      const unitSpan = unit ? ` <span class="syspanel-pwr-unit">${esc(unit)}</span>` : '';
      return `<div class="syspanel-pwr-field">
        <label class="syspanel-pwr-field-label" for="${inputId}">${esc(label)}</label>
        <span class="syspanel-pwr-field-control">${control}${unitSpan}</span>
      </div>`;
    };
    const range = s.range;
    const metaParts = [];
    if (range && Number.isFinite(Number(range.min)) && Number.isFinite(Number(range.max))) {
      metaParts.push(`取值范围 ${Number(range.min)} – ${Number(range.max)}${Number(range.step) > 0 ? `（步长 ${Number(range.step)}）` : ''}`);
    }
    if (Array.isArray(s.possibleValues) && s.possibleValues.length && !editor.rawPossible) {
      // P2 才接 possible values 的友好名（PowerReadPossibleValue）；P1 如实显示系统原始值
      metaParts.push(`可选值 ${s.possibleValues.join(' / ')}`);
    }
    const metaHtml = metaParts.length ? `<div class="syspanel-pwr-detail-meta">${esc(metaParts.join('；'))}</div>` : '';
    // 调优参考（社区经验口径）：只在表里有 rec 的设置上出现，四象限各一格
    const zhEntry = pwrZh(s.guid);
    const rec = zhEntry && zhEntry.rec;
    const recCell = (label, cell) => `<div class="syspanel-pwr-rec-cell">
        <span class="syspanel-pwr-rec-k">${esc(label)}</span>
        <span class="syspanel-pwr-rec-v">${esc(cell.v)}</span>
        <p class="syspanel-pwr-rec-why">${esc(cell.why)}</p>
      </div>`;
    const recHtml = rec ? `
      <div class="syspanel-pwr-rec">
        <div class="syspanel-pwr-rec-title">调优参考<span class="syspanel-pwr-rec-sub">社区经验值，非官方推荐；不满意可随时改回或取消编辑恢复</span></div>
        <div class="syspanel-pwr-rec-grid">
          ${recCell('台式机 · AMD', rec.desktopAmd)}
          ${recCell('台式机 · Intel', rec.desktopIntel)}
          ${recCell('笔记本 · AMD', rec.laptopAmd)}
          ${recCell('笔记本 · Intel', rec.laptopIntel)}
        </div>
      </div>` : '';
    const desc = pwrDisplayDesc(s);
    box.innerHTML = `
      <div class="syspanel-pwr-detail-name">${esc(pwrDisplayName(s))}</div>
      <div class="syspanel-pwr-detail-desc">${desc ? esc(desc) : '<span class="syspanel-pwr-muted">（该系统设置没有提供说明）</span>'}</div>
      <div class="syspanel-pwr-detail-rows">
        ${controlHtml('ac', '接通电源（AC）')}
        ${editor.dcVisible ? controlHtml('dc', '使用电池（DC）') : ''}
      </div>
      ${metaHtml}
      ${recHtml}
      ${failed ? '<div class="syspanel-pwr-unlock-note">系统拒绝解锁此设置（受保护项），当前不可编辑。</div>' : ''}
    `;
  }

  /** 输入形状闸（本地只拦「连传都传不过去」的形态：非整数/越 u32）。
   *  值域（min/max/step/可选值）不在这里拦——那是后端 apply 的单一裁量面。返回 '' 表示形状合法。 */
  function valueShapeError(raw) {
    if (raw === '' || raw === null || raw === undefined) return '空值';
    const num = Number(raw);
    if (!Number.isFinite(num)) return '不是数字';
    if (!Number.isInteger(num)) return '需要整数';
    if (num < 0 || num > 4294967295) return '超出可写入范围';
    return '';
  }

  function onDetailInput(ev) {
    const ctrl = ev.target.closest('.syspanel-pwr-input');
    if (!ctrl || !editor) return;
    const key = editor.selectedKey;
    const s = findSetting(key);
    if (!s) return;
    const side = ctrl.dataset.side === 'dc' ? 'dc' : 'ac';
    const raw = String(ctrl.value ?? '').trim();
    if (raw === '') return; // 清空中途态：不改动、不标红
    const shapeErr = valueShapeError(raw);
    if (shapeErr) {
      editor.invalidKeys.add(key);
      ctrl.classList.add('is-invalid');
    } else {
      editor.invalidKeys.delete(key);
      ctrl.classList.remove('is-invalid');
      applyLocalChange(key, s, side, Number(raw));
    }
    refreshItemMark(key);
    refreshGroupMeta();
    refreshCount();
  }

  function applyLocalChange(key, s, side, num) {
    const o = editor.origin.get(key) || { ac: null, dc: null };
    const cur = editor.changes.get(key)
      || { subgroupGuid: s.subgroupGuid, settingGuid: s.guid, ac: null, dc: null };
    if (side === 'ac') cur.ac = num;
    else cur.dc = num;
    // 归一到「净变化」：与原始值相同的边不算改动；两边都还原则整条移出表
    if (cur.ac !== null && cur.ac === o.ac) cur.ac = null;
    if (cur.dc !== null && cur.dc === o.dc) cur.dc = null;
    if (cur.ac === null && cur.dc === null) editor.changes.delete(key);
    else editor.changes.set(key, cur);
  }

  function refreshItemMark(key) {
    const s = findSetting(key);
    if (!s) return;
    document.querySelectorAll('.syspanel-pwr-item').forEach((node) => {
      if (node.dataset.key !== key) return;
      node.classList.toggle('is-changed', editor.changes.has(key));
      const sum = node.querySelector('.syspanel-pwr-item-sum');
      if (sum) sum.textContent = pwrValueSummary(s, key);
    });
  }

  function refreshGroupMeta() {
    if (!editor) return;
    document.querySelectorAll('.syspanel-pwr-group').forEach((gNode) => {
      const g = (editor.dump.subgroups || []).find((x) => String(x.guid || '') === gNode.dataset.group);
      if (!g) return;
      const total = (g.settings || []).length;
      const changed = (g.settings || []).filter((s) => editor.changes.has(pwrKey(s.subgroupGuid, s.guid))).length;
      const meta = gNode.querySelector('.syspanel-pwr-group-meta');
      if (meta) meta.textContent = changed ? `${total} 项 · ${changed} 项已改` : `${total} 项`;
    });
  }

  function refreshCount() {
    const el = document.getElementById('syspanelPwrCount');
    if (!el || !editor) return;
    const n = editor.changes.size;
    const invalid = editor.invalidKeys.size;
    let text = n > 0 ? `本次将写入 ${n} 条修改` : '本次将写入 0 条修改';
    if (invalid > 0) text += `（另有 ${invalid} 条输入无效，不会提交）`;
    el.textContent = text;
    el.classList.toggle('is-dirty', n > 0);
    const saveBtn = document.getElementById('btnSyspanelPwrSave');
    const saveApplyBtn = document.getElementById('btnSyspanelPwrSaveApply');
    const dis = editor.saving || n === 0;
    if (saveBtn) saveBtn.disabled = dis;
    if (saveApplyBtn) saveApplyBtn.disabled = dis;
    if (saveBtn) saveBtn.setAttribute('data-tip', n === 0 ? '没有需要保存的修改' : `写入 ${n} 条修改`);
    if (saveApplyBtn) saveApplyBtn.setAttribute('data-tip', n === 0 ? '没有需要保存的修改' : `写入 ${n} 条修改并切换为当前方案`);
  }

  function setEditorBusy(busy, label) {
    if (!editor) return;
    editor.saving = busy;
    const cancelBtn = document.getElementById('btnSyspanelPwrCancel');
    const saveBtn = document.getElementById('btnSyspanelPwrSave');
    const saveApplyBtn = document.getElementById('btnSyspanelPwrSaveApply');
    if (cancelBtn) { cancelBtn.disabled = busy; cancelBtn.textContent = busy ? (label || '处理中…') : '取消'; }
    if (saveBtn) saveBtn.disabled = busy || editor.changes.size === 0;
    if (saveApplyBtn) saveApplyBtn.disabled = busy || editor.changes.size === 0;
    const tree = document.getElementById('syspanelPwrTree');
    if (tree) tree.classList.toggle('is-busy', busy);
    const detail = document.getElementById('syspanelPwrDetail');
    if (detail) detail.classList.toggle('is-busy', busy);
  }

  async function editorCancel() {
    if (!editor || editor.saving) return;
    const n = editor.changes.size;
    if (n > 0) {
      const ok = await window.app?.confirmWarning?.(
        '放弃未保存的修改',
        `当前有 ${n} 条未保存的修改；放弃后这些设置恢复为进入编辑前的内容。`,
        '放弃修改',
        '继续编辑',
      );
      if (!ok) return;
    }
    // 进会话时解锁的显隐属性按后端保存的完整快照回写（渲染层不伪造属性字）
    setEditorBusy(true, '正在恢复…');
    try {
      const resp = await window.api.syspanel.powerSettingsRevert(editor.schemeGuid, editor.sessionId);
      if (resp && resp.success) {
        exitEditor();
        await loadPower();
        pwrToast('info', n > 0 ? '已放弃修改，设置恢复到进入编辑前的状态' : '已退出编辑');
      } else {
        const d = (resp && resp.data) || {};
        const items = (d.failed || []).map((f) => f.message).filter(Boolean).join('；');
        pwrToast('error', `恢复未完全成功：${items || (resp && resp.message) || '未知原因'}；可重试取消。`);
      }
    } catch (e) {
      pwrToast('error', '恢复异常：' + (e && e.message ? e.message : String(e)));
    } finally {
      setEditorBusy(false);
    }
  }

  async function editorSave(applyActive) {
    if (!editor || editor.saving) return;
    const list = Array.from(editor.changes.values());
    if (!list.length) return;
    if (applyActive) {
      const ok = await window.app?.confirmWarning?.(
        '保存并应用',
        `将写入 ${list.length} 条修改，并把「${editor.schemeName}」设为当前方案。`,
        '保存并应用',
        '取消',
        '切换为当前方案后系统会立刻按新设置调度；写入前逐条校验范围，失败会如实报出。',
      );
      if (!ok) return;
    }
    setEditorBusy(true, '写入中…');
    try {
      const resp = await window.api.syspanel.powerSettingsApply(editor.schemeGuid, list, !!applyActive);
      if (resp && resp.success) {
        const d = resp.data || {};
        const written = (d.written || []).length;
        exitEditor();
        await loadPower();
        pwrToast('info', applyActive
          ? `已保存 ${written} 条修改，并切换为当前方案`
          : `已保存 ${written} 条修改`);
      } else {
        // stopped 语义：已写入的不回滚，停在哪一条就报哪一条（不假装整体成功）
        const d = (resp && resp.data) || {};
        const written = (d.written || []).length;
        const items = (d.failed || []).map((f) => f.message).filter(Boolean).join('；');
        pwrToast('error', `保存未完成（已写入 ${written} 条后中止）：${items || (resp && resp.message) || '未知原因'}`);
      }
    } catch (e) {
      pwrToast('error', '保存异常：' + (e && e.message ? e.message : String(e)));
    } finally {
      setEditorBusy(false);
    }
  }

  // ==================== 虚拟内存（只读 + 手写编辑，v0.4.9 §3.6 写侧） ====================

  function renderPagefile(state) {
    const el = mountPagefile();
    if (!el) return;
    const managed = !!state.managed;
    const entries = Array.isArray(state.entries) ? state.entries : [];
    const modeText = managed ? '系统托管（自动管理分页文件大小）' : '手动配置';
    const rows = entries.length
      ? entries.map((e) => {
          const initMb = Number(e.initialMb) || 0;
          const maxMb = Number(e.maxMb) || 0;
          const fmt = (n) => (n === 0 ? '0 MB' : (n >= 1024 ? window.ds.fmtBytes(n * 1024 * 1024) : n + ' MB'));
          return `<tr><td>${esc(e.path || '(未设置)')}</td><td>${esc(fmt(initMb))}</td><td>${esc(fmt(maxMb))}</td></tr>`;
        }).join('')
      : '<tr><td colspan="3" class="empty-cell">未读到 PagingFiles 项（可能全在托管模式）</td></tr>';
    // 提示只留卡片头没覆盖的那一条事实：「改前自动备份 · 需重启生效」卡片头已写；
    // 而原实现把 markdown 的 ** 直接写进了 HTML（页面上显示成两颗星号），整段三行也太长。
    el.innerHTML = `
      <p class="syspanel-pf-mode">${esc(modeText)}</p>
      <table class="syspanel-pf-table">
        <thead><tr><th>路径</th><th>初始大小</th><th>最大值</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p class="syspanel-pf-hint">全部卷都关掉会让物理内存耗尽时蓝屏；写前的原配置已备份，可在「备份还原」导入回退。</p>
      <div class="syspanel-pf-actions">
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPfEdit">编辑配置</button>
      </div>
      <div id="syspanelPfEditor" style="display:none"></div>
    `;
    document.getElementById('btnSyspanelPfEdit')?.addEventListener('click', () => enterPfEditor(state));
  }

  /** 进入编辑态：把当前 state 摊成表单。用户可以直接改 managed 复选框、增删卷、改 MB 数。 */
  function enterPfEditor(state) {
    const mount = document.getElementById('syspanelPfEditor');
    const btn = document.getElementById('btnSyspanelPfEdit');
    if (!mount) return;
    if (btn) btn.style.display = 'none';
    mount.style.display = '';
    const managed = !!state.managed;
    const entries = (Array.isArray(state.entries) ? state.entries : []).map((e) => {
      // 从 "C:\pagefile.sys 8192 16384" 反推 drive/initial/max；失败退到 C:
      const m = String(e.path || '').match(/^([A-Za-z]:)/);
      return {
        drive: m ? m[1].toUpperCase() : 'C:',
        initialMb: Number(e.initialMb) || 0,
        maxMb: Number(e.maxMb) || 0,
      };
    });
    const renderRows = (list) => list.map((e, i) => `
      <tr>
        <td><input type="text" class="syspanel-pf-input syspanel-pf-drive" data-idx="${i}" value="${escAttr(e.drive)}" maxlength="2" data-tip="盘符，如 C: 或 D:" /></td>
        <td><input type="number" class="syspanel-pf-input" data-idx="${i}" data-field="initialMb" value="${e.initialMb}" min="0" max="1048576" step="1" /></td>
        <td><input type="number" class="syspanel-pf-input" data-idx="${i}" data-field="maxMb" value="${e.maxMb}" min="0" max="1048576" step="1" /></td>
        <td><button type="button" class="btn btn-secondary btn-small" data-pf-remove="${i}">删除</button></td>
      </tr>`).join('');
    mount.innerHTML = `
      <label class="syspanel-pf-managed">
        <input type="checkbox" id="syspanelPfManaged" ${managed ? 'checked' : ''} />
        <span>由系统自动管理分页文件大小（推荐；勾选则下方配置不生效）</span>
      </label>
      <div id="syspanelPfManualArea" class="syspanel-pf-manual-area">
        <table class="syspanel-pf-table">
          <thead><tr><th>盘符</th><th>初始 (MB)</th><th>最大 (MB)</th><th></th></tr></thead>
          <tbody id="syspanelPfTbody">${renderRows(entries)}</tbody>
        </table>
        <div class="syspanel-pf-tools">
          <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPfAdd">+ 添加卷</button>
        </div>
      </div>
      <div class="syspanel-pf-actions">
        <button type="button" class="btn btn-primary btn-small" id="btnSyspanelPfApply">应用配置</button>
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPfCancel">取消</button>
      </div>
    `;
    const managedBox = document.getElementById('syspanelPfManaged');
    const manualArea = document.getElementById('syspanelPfManualArea');
    const syncManualArea = () => { if (manualArea) manualArea.style.display = managedBox?.checked ? 'none' : ''; };
    managedBox?.addEventListener('change', syncManualArea);
    syncManualArea();
    document.getElementById('btnSyspanelPfAdd')?.addEventListener('click', () => {
      const list = collectPfForm();
      list.push({ drive: 'D:', initialMb: 0, maxMb: 4096 });
      document.getElementById('syspanelPfTbody').innerHTML = renderRows(list);
    });
    mount.querySelectorAll('[data-pf-remove]').forEach((b) => b.addEventListener('click', () => {
      const idx = Number(b.dataset.pfRemove);
      const list = collectPfForm();
      list.splice(idx, 1);
      document.getElementById('syspanelPfTbody').innerHTML = renderRows(list);
    }));
    document.getElementById('btnSyspanelPfCancel')?.addEventListener('click', () => {
      mount.style.display = 'none';
      if (btn) btn.style.display = '';
    });
    document.getElementById('btnSyspanelPfApply')?.addEventListener('click', () => applyPagefile(managedBox?.checked, collectPfForm()));
  }

  function collectPfForm() {
    const rows = document.querySelectorAll('#syspanelPfTbody tr');
    const list = [];
    rows.forEach((tr) => {
      const driveEl = tr.querySelector('.syspanel-pf-drive');
      const initEl = tr.querySelector('[data-field="initialMb"]');
      const maxEl = tr.querySelector('[data-field="maxMb"]');
      if (!driveEl || !initEl || !maxEl) return;
      list.push({
        drive: driveEl.value.trim(),
        initialMb: Number(initEl.value) || 0,
        maxMb: Number(maxEl.value) || 0,
      });
    });
    return list;
  }

  async function applyPagefile(managed, entries) {
    if (!window.api?.syspanel?.pagefileApply) {
      window.app?.toast?.('warning', '当前环境不支持写虚拟内存');
      return;
    }
    // 高危二次确认：AGENTS §3 危险能力显式确认。文案里明说蓝屏风险与重启需求，
    // 免得用户只看到"应用"按钮就点下去。位置参数形态（AGENTS §5 confirm 禁对象）。
    const ok = await window.app?.confirmDanger?.(
      '修改虚拟内存配置',
      `即将把虚拟内存改为「${managed ? '系统托管' : '手动配置（' + entries.length + ' 个卷）'}」。\n`
        + '\n必须知道：\n'
        + '· 需要**重启**才生效；\n'
        + '· 全部关完会让物理内存耗尽时直接蓝屏，Trim 参数校验层会拒这种配置；\n'
        + '· 改前当前配置已备份，可通过导入备份 JSON 手动回退。',
      '我已了解，应用',
      '取消',
      '此操作会修改 HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management。'
    );
    if (!ok) return;
    const btn = document.getElementById('btnSyspanelPfApply');
    if (btn) { btn.disabled = true; btn.textContent = '写入中…'; }
    try {
      // v4-K05：高危凭据由本调用点在红档确认**之后**显式传入（桥接层不再硬编码），
      // 后端 syspanel.rs 以 confirmedHighRisk 为闸 —— 证明确认在调用点真的发生过。
      const resp = await window.api.syspanel.pagefileApply(!!managed, entries, !!ok);
      if (resp && resp.success) {
        const data = resp.data || {};
        window.app?.toast?.('info', '虚拟内存配置已写入并回读校验通过；**需要重启生效**');
        // 重渲染只读视图（走 loadPagefile）
        await loadPagefile();
        if (data.backupPath) {
          const el = mountPagefile();
          if (el) {
            const hint = document.createElement('p');
            hint.className = 'syspanel-pf-hint syspanel-pf-backup';
            hint.textContent = '本次改前配置已备份到：' + data.backupPath;
            el.appendChild(hint);
          }
        }
      } else {
        window.app?.toast?.('error', (resp && resp.message) || '写入失败');
      }
    } catch (e) {
      window.app?.toast?.('error', '写入异常：' + (e && e.message ? e.message : String(e)));
    } finally {
      const b2 = document.getElementById('btnSyspanelPfApply');
      if (b2) { b2.disabled = false; b2.textContent = '应用配置'; }
    }
  }

  // ==================== 加载与初始化 ====================

  async function loadPower() {
    if (!window.api?.syspanel?.powerPlanGet) {
      renderPowerEmpty('当前环境不支持读取电源方案');
      return;
    }
    try {
      const resp = await window.api.syspanel.powerPlanGet();
      const data = resp && resp.success ? resp.data : null;
      if (!data) { renderPowerEmpty((resp && resp.message) || '读取电源方案失败'); return; }
      renderPower(data);
      powerLoaded = true;
    } catch (e) {
      renderPowerEmpty('读取失败：' + (e && e.message ? e.message : String(e)));
    }
  }

  async function loadPagefile() {
    if (!mountPagefile()) return;
    if (!window.api?.syspanel?.pagefileState) {
      mountPagefile().innerHTML = '<p class="empty-state"><span>当前环境不支持读取虚拟内存</span></p>';
      return;
    }
    try {
      const resp = await window.api.syspanel.pagefileState();
      const data = resp && resp.success ? resp.data : null;
      if (!data) {
        mountPagefile().innerHTML = `<p class="empty-state"><span>${esc((resp && resp.message) || '读取虚拟内存失败')}</span></p>`;
        return;
      }
      renderPagefile(data);
    } catch (e) {
      mountPagefile().innerHTML = `<p class="empty-state"><span>读取失败：${esc(e && e.message ? e.message : String(e))}</span></p>`;
    }
  }

  /** app.js 交付的提权意图（新实例首帧后事件）。未 init 时先收着，init 后消费。 */
  function onEditIntent(intent) {
    pendingEditIntent = intent || null;
    if (inited) consumePendingEditIntent();
  }

  function consumePendingEditIntent() {
    const st = window.app?.getState?.();
    const intent = pendingEditIntent || st?.pendingPowerEditIntent;
    pendingEditIntent = null;
    if (st) st.pendingPowerEditIntent = null;
    if (!intent || !intent.schemeGuid || editor) return;
    pwrToast('info', '已切换为管理员权限，正在进入电源计划编辑');
    enterPowerEditor(intent.schemeGuid);
  }

  function init() {
    if (inited) return;
    inited = true;
    document.getElementById('btnSyspanelPowerRefresh')?.addEventListener('click', () => {
      if (editor) { pwrToast('info', '正在编辑中，请先保存或取消'); return; }
      loadPower();
    });
    document.getElementById('btnSyspanelPowerNew')?.addEventListener('click', onNewPowerPlan);
    // 首帧进 settings 页时拉一次；后续靠"刷新"按钮再拉。
    if (!powerLoaded) {
      loadPower();
    }
    loadPagefile();
    // 提权重启接回：事件可能先于本模块 init 到达（app.js 存了 appState），也可能由 onEditIntent 暂存
    consumePendingEditIntent();
  }

  window.syspanel = { init, loadPower, loadPagefile, onEditIntent };

  // 延迟加载脚本守卫（AGENTS §4 check-idle-scripts 断言 1）：顶层 DOMContentLoaded 注册
  // 必须在 readyState 判定内；本文件是"按需注入"，注入时通常已 Completed，走 else 立即 init。
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => init());
  } else {
    init();
  }
})();
