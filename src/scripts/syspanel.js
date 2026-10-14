// syspanel.js — 电源计划读写 + 逐设置编辑 + 虚拟内存读写（P2 §3.6 RAINZ 对标；v5 P1 编辑器）
// 挂在「Windows设置」页（2026-10-15 从设置页迁出、独立成侧边栏入口）；由 app.js 的
// PAGE_SCRIPTS['windows-settings'] 按需注入、MODULES_NEEDING_INIT 显式调 init。
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
  /** 编辑器弹窗 ctrl（会话期间非 null；关闭即销毁） */
  let editorModal = null;
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
      desc: '硬盘空闲多久后允许进入省电模式（毫秒）。值越大越不容易进省电、响应越快；设 0 = 一直保持全速。',
      rec: {
        desktopAmd: { v: '0 或 2000', why: '0 = 一直全速、延迟最优；2000 是「保留少量省电」的折中（视频作者口径）。锐龙平台上深层链路低功耗态的兼容性偶有报告，禁用可顺带规避。' },
        desktopIntel: { v: '0 或 2000', why: '同左；想兼顾一点点省电就选 2000。' },
        laptopAmd: { v: '保持默认', why: '续航优先；若出现与盘唤醒相关的卡顿，可试 0 对比。' },
        laptopIntel: { v: '保持默认', why: '续航优先，同左。' },
      },
    },
    'd3d55efd-c1ff-424e-9dc3-441be7833010': {
      name: '次 NVMe 空闲超时',
      desc: '硬盘在主省电状态里再待多久后，允许继续进入更深的省电状态（毫秒）。',
      rec: {
        desktopAmd: { v: '0 或 200', why: '不让硬盘进入更深的省电态（视频口径给 200）；理由同上一条。' },
        desktopIntel: { v: '0 或 200', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '保持默认即可。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    'fc95af4d-40e7-4b6d-835a-56d131dbc80e': {
      name: '主 NVMe 电源状态切换延迟容限',
      desc: '允许硬盘进入多深的省电模式：只有「进出延迟之和（ENLAT+EXLAT）」不超过本设定值（微秒）的省电档位才会被使用；值越小越保守。',
      rec: {
        desktopAmd: { v: '0', why: '只允许进入没有额外进出延迟代价的档位：省电深度与响应速度之间取响应优先。' },
        desktopIntel: { v: '0', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '允许系统按续航策略进入浅省电态。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    'dbc9e238-6de9-49e3-92cd-8c2b4946b472': {
      name: '次 NVMe 电源状态切换延迟容限',
      desc: '硬盘在主省电状态停留一段时间后，允许进入多深的省电模式：只有「进出延迟之和（ENLAT+EXLAT）」不超过本设定值（微秒）的档位才会被使用。',
      rec: {
        desktopAmd: { v: '0', why: '与上一条配套：不让硬盘进入更深的省电态。' },
        desktopIntel: { v: '0', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '保持默认。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '0b2d69d7-a2a1-449c-9680-f91c70521c60': {
      name: 'AHCI 链路电源管理 — HIPM/DIPM',
      desc: 'SATA 硬盘链路的省电档位：Active = 不省电（最稳）；HIPM / DIPM / HIPM+DIPM = 逐级允许链路省电。',
      rec: {
        desktopAmd: { v: 'Active', why: '禁用 SATA 链路省电：消除链路唤醒延迟与偶发掉盘（视频口径：选择 active）。较老的 AMD 芯片组上 SATA 链路低功耗的兼容性问题更常被报告。' },
        desktopIntel: { v: 'Active', why: '同左；Intel 平台问题相对少见，遇到 SATA 链路类卡顿再改也可以。' },
        laptopAmd: { v: '保持默认', why: '续航优先；出现掉盘/卡顿再改 Active。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    'dab60367-53fe-4fbc-825e-521d069d2456': {
      name: 'AHCI 链路电源管理 — 自适应',
      desc: '让硬盘链路自动从 Partial（浅睡）过渡到 Slumber（深睡）。',
      rec: {
        desktopAmd: { v: '禁用', why: '配合上一条统一关闭 SATA 链路省电。' },
        desktopIntel: { v: '禁用', why: '同左。' },
        laptopAmd: { v: '保持默认（启用）', why: '续航优先。' },
        laptopIntel: { v: '保持默认（启用）', why: '同左。' },
      },
    },
    '5e8c011f-01bc-4821-b947-deffa95af8d2': {
      name: '任意 NVMe 盘 · 非运行态 APST 空闲转换时间（毫秒）',
      desc: '任意 NVMe 盘在省电状态下：空闲多久后允许切换省电档位。硬盘固件自己管省电用的，日常不用动。',
    },
    '7f68c523-7536-4a79-b339-0ba0998f5dc4': {
      name: '任意 NVMe 盘 · 运行态 APST 空闲转换时间（毫秒）',
      desc: '任意 NVMe 盘在工作状态下：空闲多久后允许切换省电档位。硬盘固件自己管省电用的，日常不用动。',
    },
    '54bbd65b-b333-4808-ae71-461b696bf60e': {
      name: '混合 NAND 盘 · 非运行态 APST 空闲转换时间（毫秒）',
      desc: '混合 NAND 盘在省电状态下：空闲多久后允许切换省电档位。硬盘固件自己管省电用的，日常不用动。',
    },
    'b6c43707-23d2-46d4-bd1a-ac91685c76bb': {
      name: '混合 NAND 盘 · 运行态 APST 空闲转换时间（毫秒）',
      desc: '混合 NAND 盘在工作状态下：空闲多久后允许切换省电档位。硬盘固件自己管省电用的，日常不用动。',
    },
    '4016abef-65af-42a2-9939-45cb45e92634': {
      name: '混合 Optane 盘 · 非运行态 APST 空闲转换时间（毫秒）',
      desc: '混合 Optane 盘在省电状态下：空闲多久后允许切换省电档位。硬盘固件自己管省电用的，日常不用动。',
    },
    'bb50ccc4-ef9f-4008-a470-e6ea6737f152': {
      name: '混合 Optane 盘 · 运行态 APST 空闲转换时间（毫秒）',
      desc: '混合 Optane 盘在工作状态下：空闲多久后允许切换省电档位。硬盘固件自己管省电用的，日常不用动。',
    },
    // ---- USB（2a737441）----
    'd4e98f31-5ffe-4ce1-be31-1b38b384c009': {
      name: 'USB 3 链路电源管理',
      desc: 'USB 3 接口空闲时的省电策略。',
      rec: {
        desktopAmd: { v: '关闭', why: 'USB 3 链路低功耗态（U1/U2 等）是外设偶发断连、无线接收器失联、外置硬盘掉盘的常见根因（视频口径：选择 Off）；台式没有续航压力，直接关最稳。' },
        desktopIntel: { v: '关闭', why: '同左；外设一切正常且在意省电的话，保留默认也可以。' },
        laptopAmd: { v: '保持默认', why: '续航优先；出现外设掉线再关。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '0853a681-27c8-4100-a2fd-82013e970683': {
      name: 'USB 集线器选择性挂起超时',
      desc: 'USB 集线器空闲多久后被允许挂起（毫秒）。',
      rec: {
        desktopAmd: { v: '100000', why: '把挂起超时拉到约 100 秒、几乎不触发（视频口径「10 万」），避免键鼠/接收器被挂起后唤醒迟滞或失联。' },
        desktopIntel: { v: '100000', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '续航优先；键鼠迟滞再调。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '498c044a-201b-4631-a522-5c744ed4e678': {
      name: '对所有传输描述符设置 IOC',
      desc: '给每个 USB 传输描述符都发完成中断（调试/特殊用途，日常不用动）。',
    },
    // ---- 只带调优参考、不需要翻译的设置（名称与描述系统已出中文）----
    'ee12f906-d277-404b-b6da-e5fa1a576df5': { // PCI Express 链接状态电源管理（ASPM）
      rec: {
        desktopAmd: { v: '关闭', why: 'PCIe 链路省电（ASPM）是延迟与兼容性问题的常见来源（掉盘、USB 断连、卡顿）；台式没有续航压力，直接关最稳（视频口径：选择关闭）。' },
        desktopIntel: { v: '关闭', why: '同左；Intel 平台的 ASPM 实现较稳，外设一切正常也可保留默认。' },
        laptopAmd: { v: '保持默认', why: '续航优先；出现 PCIe/USB 类异常再关。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    'be337238-0d82-4146-a960-4f3749d470c7': { // 处理器性能提升模式（Boost mode）
      rec: {
        desktopAmd: { v: '高效积极且有保障', why: '保留加速但不长时间超功耗跑，护硬件寿命；不要选「激进/高性能」（视频口径：AMD、Intel 都选它）。' },
        desktopIntel: { v: '高效积极且有保障', why: '同左。' },
        laptopAmd: { v: '保持默认（通常为「启用」）', why: '笔记本散热余量小，激进档容易拉高温度与风扇噪音。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb': { // 允许节流状态
      rec: {
        desktopAmd: { v: '禁用', why: '不让 CPU 用节流降频兜底，减少游戏里的频率抖动（视频口径：AMD 关闭）。' },
        desktopIntel: { v: '启用', why: 'Intel 平台保留节流更稳（视频口径：Intel 启用）。' },
        laptopAmd: { v: '保持默认（启用）', why: '笔记本靠它压温度与功耗，不建议关。' },
        laptopIntel: { v: '保持默认（启用）', why: '同左。' },
      },
    },
    '36687f9e-e3a5-4dbf-b1dc-15eb381c6863': { // 处理器能源性能首选策略（EPP）
      rec: {
        desktopAmd: { v: '5', why: '偏性能侧的小幅让步（视频口径：AMD 给 5）。数值越接近 0 越偏性能、越接近 100 越偏省电。' },
        desktopIntel: { v: '0', why: '纯性能优先（视频口径：Intel 给 0）。' },
        laptopAmd: { v: '保持默认', why: '默认值随电源模式自动协商，续航优先不动。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '12a0ab44-fe28-4fa9-b3bd-4b64f44960a6': { // 处理器性能降低阈值
      rec: {
        desktopAmd: { v: '10', why: '降频更迟钝、频率保持更久（视频口径：AMD 10）。' },
        desktopIntel: { v: '5', why: '同左（视频口径：Intel 5）。' },
        laptopAmd: { v: '保持默认', why: '续航优先不动。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '7d24baa7-0b84-480f-840c-1b0743c00f5f': { // 处理器性能历史计数
      rec: {
        desktopAmd: { v: '1', why: '采样窗口更短、对负载变化反应更快（视频口径：AMD 1）。' },
        desktopIntel: { v: '3', why: '同左（视频口径：Intel 3）。' },
        laptopAmd: { v: '保持默认', why: '续航优先不动。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '4b70f900-cdd9-4e66-aa26-ae8417f98173': { // 延迟敏感度提示处理器能源性能首选项
      rec: {
        desktopAmd: { v: '50', why: '延迟敏感负载下给性能留一半余量（视频口径：AMD 50）。' },
        desktopIntel: { v: '100', why: '完全按性能响应（视频口径：Intel 100）。' },
        laptopAmd: { v: '保持默认', why: '续航优先不动。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '94d3a615-a899-4ac5-ae2b-e4d8f634367f': { // 系统散热方式
      rec: {
        desktopAmd: { v: '主动', why: '优先用风扇散热、少用降频（视频口径：主动）；台式散热余量足，性能更稳。' },
        desktopIntel: { v: '主动', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '笔记本默认往往是「被动」优先，静音；想更凉快再改主动。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
    '2430ab6f-a520-44a2-9601-f7f23b5134b1': { // 处理器性能内核休止并发阈值
      rec: {
        desktopAmd: { v: '95–98', why: '别给 100：给满会让核心停放进退来回震荡；95–98 区间任选、可自行对比（视频口径）。' },
        desktopIntel: { v: '95–98', why: '同左。' },
        laptopAmd: { v: '保持默认', why: '笔记本核心停放省电更重要，不建议收紧。' },
        laptopIntel: { v: '保持默认', why: '同左。' },
      },
    },
  };

  // 枚举设置的「编号 → 人话」表（v5 P2）：取值名取微软公开枚举（视频口径的「高效积极且有保障」即此）。
  // 值域随机型/系统版本变化——表里没有的编号照常显示原数字，不隐藏、不猜测。
  const PWR_ENUM_ZH = {
    // 处理器性能提升模式（Boost mode）0–5 档；6 档各平台命名不一，暂不登记
    'be337238-0d82-4146-a960-4f3749d470c7': {
      0: '禁用', 1: '启用', 2: '激进', 3: '高效启用', 4: '高效激进', 5: '高效积极且有保障',
    },
    // 允许节流状态
    '3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb': { 0: '禁用', 1: '启用' },
    // 系统散热方式
    '94d3a615-a899-4ac5-ae2b-e4d8f634367f': { 0: '被动（只降频）', 1: '主动（先转风扇）' },
  };

  function pwrEnumZh(settingGuid, value) {
    const map = PWR_ENUM_ZH[String(settingGuid || '').toLowerCase()];
    if (!map) return '';
    return map[value] || '';
  }

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
    if (!window.modal?.create) {
      pwrToast('warning', '当前环境不支持编辑弹窗');
      return;
    }
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
      searchText: new Map(), // v5 P2 搜索索引：key → 拼接后的可搜文本（小写）
      compareCache: new Map(), // v5 P2 对照缓存：key → { loading, rows }
      dcVisible: dump.platformRole === 'mobile' || dump.platformRole === 'slate',
      collapsed: new Set(), // 默认全部折叠：初始先塞全部组名，点开再删
      selectedKey: '',
      saving: false,
    };
    for (const g of dump.subgroups || []) {
      editor.collapsed.add(String(g.guid || ''));
      for (const s of g.settings || []) {
        const key = pwrKey(s.subgroupGuid, s.guid);
        editor.origin.set(key, { ac: s.valueAc, dc: s.valueDc });
        const zhEntryForSearch = pwrZh(s.guid);
        editor.searchText.set(key, [
          s.name, zhEntryForSearch?.name, s.description, zhEntryForSearch?.desc,
        ].filter(Boolean).join(' ').toLowerCase());
      }
    }
    // 独立弹窗承载编辑器（2026-10-15 用户裁定：不再内嵌卡片区）。模态遮罩天然挡住卡片
    // 头部按钮，不必再做显隐；Esc/遮罩/× 一律转「取消」流程（先确认、再回滚、成功才关）。
    editorModal = window.modal.create({
      id: 'syspanelPwrEditorModal',
      title: '编辑电源计划',
      bodyHtml: '<div id="syspanelPwrEditorMount"></div>',
      footerHtml: `
        <span class="model-picker-spacer"></span>
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPwrCancel">取消</button>
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPwrSave">确定并保存</button>
        <button type="button" class="btn btn-primary btn-small" id="btnSyspanelPwrSaveApply">保存并应用</button>
      `,
      modalClass: 'syspanel-pwr-modal',
      width: 'min(1180px, 94vw)',
      onRequestClose: () => { editorCancel(); return false; },
    });
    renderEditor();
  }

  function exitEditor() {
    editor = null;
    if (editorModal) {
      editorModal.close();
      editorModal = null;
    }
  }

  function renderEditor() {
    const el = document.getElementById('syspanelPwrEditorMount');
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
          <div class="syspanel-pwr-tree-col">
            <input type="search" class="syspanel-pwr-input syspanel-pwr-search" id="syspanelPwrSearch"
                   placeholder="搜索设置（名称/说明关键字）" autocomplete="off">
            <div class="syspanel-pwr-tree" id="syspanelPwrTree">${groupsHtml || '<p class="empty-state"><span>本方案没有枚举到可编辑的设置</span></p>'}</div>
          </div>
          <div class="syspanel-pwr-detail" id="syspanelPwrDetail">
            <p class="empty-state"><span>从左侧选一项设置查看并修改取值</span></p>
          </div>
        </div>
      </div>`;
    document.getElementById('syspanelPwrTree')?.addEventListener('click', onTreeClick);
    const detailBox = document.getElementById('syspanelPwrDetail');
    // select 在 WebView2 里 input 与 change 都会来；两个都绑，applyLocalChange 幂等
    detailBox?.addEventListener('input', onDetailInput);
    detailBox?.addEventListener('change', onDetailInput);
    detailBox?.addEventListener('click', onDetailClick);
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
    document.getElementById('syspanelPwrSearch')?.addEventListener('input', applySearchFilter);
    refreshGroupMeta();
    refreshCount();
  }

  /** v5 P2 搜索过滤：命中项显示、组按需显隐；清空后恢复原有折叠状态（不改 editor.collapsed）。 */
  function applySearchFilter() {
    if (!editor) return;
    const q = String(document.getElementById('syspanelPwrSearch')?.value || '').trim().toLowerCase();
    document.querySelectorAll('.syspanel-pwr-group').forEach((gNode) => {
      const gGuid = gNode.dataset.group || '';
      let visible = 0;
      gNode.querySelectorAll('.syspanel-pwr-item').forEach((node) => {
        const hit = !q || String(editor.searchText.get(node.dataset.key || '') || '').includes(q);
        node.hidden = !hit;
        if (hit) visible += 1;
      });
      const list = gNode.querySelector('.syspanel-pwr-group-items');
      const head = gNode.querySelector('.syspanel-pwr-group-head');
      const caret = head?.querySelector('.syspanel-pwr-caret');
      if (q) {
        // 搜索态：有命中的组强制展开（不回写折叠状态，清空即还原）
        gNode.hidden = visible === 0;
        list?.removeAttribute('hidden');
        head?.setAttribute('aria-expanded', 'true');
        if (caret) caret.textContent = '▾';
      } else {
        const collapsed = editor.collapsed.has(gGuid);
        gNode.hidden = false;
        list?.toggleAttribute('hidden', collapsed);
        head?.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
        if (caret) caret.textContent = collapsed ? '▸' : '▾';
      }
    });
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
      const possible = Array.isArray(s.possibleValues) ? s.possibleValues : [];
      // 宽值域（枚举项很多，如 APST 的 0–255）本质是数值输入：用输入框而不是长下拉
      // （2026-10-15 用户反馈）。后端 apply 的校验以 range 为准（range 存在时 possible
      // 不再参与），所以输入框的 min/max/step 直接取 range；range 缺失的宽枚举取
      // possible 的 min/max 作界（与后端「possible 兜底校验」一致）。
      const useSelect = possible.length > 0 && possible.length <= 32;
      let control;
      if (useSelect) {
        // 当前值可能不在系统给出的枚举内（真机实测存在这种合法既成事实，如
        // 「合上盖子操作」当前 1 / 枚举 0,2,3,6）：补一个选中项如实显示，绝不静默落到第一项。
        const inEnum = val !== null && val !== undefined && possible.some((v) => Number(v) === Number(val));
        const curName = val !== null && val !== undefined ? pwrEnumZh(s.guid, val) : '';
        const curOpt = (!inEnum && val !== null && val !== undefined)
          ? `<option value="${escAttr(String(val))}" selected>${esc(curName ? `${val}（${curName}）` : String(val))}（当前值）</option>`
          : '';
        const opts = possible
          .map((v) => {
            const zhName = pwrEnumZh(s.guid, v);
            return `<option value="${escAttr(String(v))}"${Number(val) === Number(v) ? ' selected' : ''}>${esc(zhName ? `${v}（${zhName}）` : String(v))}</option>`;
          })
          .join('');
        control = `<select class="syspanel-pwr-input" id="${inputId}" data-side="${side}"${dis}>${curOpt}${opts}</select>`;
      } else {
        const r = s.range || {};
        let minNum = Number.isFinite(Number(r.min)) ? Number(r.min) : null;
        let maxNum = Number.isFinite(Number(r.max)) ? Number(r.max) : null;
        let stepNum = Number.isFinite(Number(r.step)) && Number(r.step) > 0 ? Number(r.step) : null;
        if (minNum === null && possible.length) { minNum = Math.min(...possible); maxNum = Math.max(...possible); stepNum = null; }
        const minAttr = minNum !== null ? ` min="${minNum}"` : '';
        const maxAttr = maxNum !== null ? ` max="${maxNum}"` : '';
        const stepAttr = stepNum !== null ? ` step="${stepNum}"` : '';
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
    if (Array.isArray(s.possibleValues) && s.possibleValues.length && s.possibleValues.length <= 32) {
      // 只有窄枚举在元信息里列出（宽值域本质是数值输入，界已由「取值范围」承担）
      metaParts.push(`可选值 ${s.possibleValues.map((v) => {
        const zhName = pwrEnumZh(s.guid, v);
        return zhName ? `${v}=${zhName}` : String(v);
      }).join(' / ')}`);
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
    const regeditBtn = `<div class="syspanel-pwr-detail-actions">
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPwrRegedit" data-tip="打开注册表编辑器并定位到该设置">在注册表中查看</button>
      </div>`;
    box.innerHTML = `
      <div class="syspanel-pwr-detail-name">${esc(pwrDisplayName(s))}</div>
      <div class="syspanel-pwr-detail-desc">${desc ? esc(desc) : '<span class="syspanel-pwr-muted">（该系统设置没有提供说明）</span>'}</div>
      <div class="syspanel-pwr-detail-rows">
        ${controlHtml('ac', '接通电源（AC）')}
        ${editor.dcVisible ? controlHtml('dc', '使用电池（DC）') : ''}
      </div>
      ${metaHtml}
      <div id="syspanelPwrCompare"></div>
      ${regeditBtn}
      ${recHtml}
      ${failed ? '<div class="syspanel-pwr-unlock-note">系统拒绝解锁此设置（受保护项），当前不可编辑。</div>' : ''}
    `;
    ensureCompare(key, s);
  }

  /** v5 P2 各方案数值对照：懒加载 + 会话内缓存（同一 key 只拉一次）。 */
  function ensureCompare(key, s) {
    const mount = document.getElementById('syspanelPwrCompare');
    if (!mount || !editor) return;
    const cached = editor.compareCache.get(key);
    if (cached && !cached.loading) { renderCompare(mount, key, cached.rows); return; }
    if (cached && cached.loading) return;
    editor.compareCache.set(key, { loading: true, rows: [] });
    window.api.syspanel.powerSettingsCompare(s.subgroupGuid, s.guid)
      .then((resp) => {
        const rows = resp && resp.success ? (resp.data?.rows || []) : [];
        editor?.compareCache.set(key, { loading: false, rows });
        if (editor && editor.selectedKey === key) {
          const m2 = document.getElementById('syspanelPwrCompare');
          if (m2) renderCompare(m2, key, rows);
        }
      })
      .catch(() => editor?.compareCache.set(key, { loading: false, rows: [] }));
  }

  function renderCompare(mount, key, rows) {
    if (!editor || !rows.length) { mount.innerHTML = ''; return; }
    const fmt = (v) => (v === null || v === undefined ? '—' : String(v));
    const items = rows.map((r) => {
      const editing = String(r.schemeGuid || '').toLowerCase() === editor.schemeGuid;
      const suffix = editing ? '（正在编辑）' : (r.active ? '（当前使用）' : '');
      const value = editor.dcVisible ? `${fmt(r.ac)} / ${fmt(r.dc)}` : fmt(r.ac);
      return `<div class="syspanel-pwr-compare-row${editing ? ' is-active' : ''}">
        <span class="syspanel-pwr-compare-k">${esc(String(r.schemeName || r.schemeGuid) + suffix)}</span>
        <span class="syspanel-pwr-compare-v">${esc(value)}</span>
      </div>`;
    }).join('');
    mount.innerHTML = `
      <div class="syspanel-pwr-compare">
        <div class="syspanel-pwr-compare-title">各方案对照${editor.dcVisible ? '（AC / DC）' : '（AC）'}</div>
        <div class="syspanel-pwr-compare-rows">${items}</div>
      </div>`;
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

  // ==================== v5 P2 外部改动自动同步 ====================
  // 口径：用「窗口重新激活时自动重读」覆盖「用户切到别的工具改了设置、再切回来」的真实场景。
  // 未用 PowerSettingRegisterNotification —— 该系统 API 只支持按特定 GUID 注册（不提供
  // 「任意设置变化」的通配通知），拿它做「别的工具改了自动刷新」是假承诺。

  let lastAutoRefreshAt = 0;

  function scheduleAutoRefresh() {
    if (document.visibilityState !== 'visible') return;
    const now = Date.now();
    if (now - lastAutoRefreshAt < 5000) return; // 5s 节流：来回切窗口不反复重读
    lastAutoRefreshAt = now;
    if (editor) void refreshEditorAfterExternalChange();
    else if (inited) void loadPower();
  }

  /** 编辑态：无未保存改动才静默重读；与旧值逐项比对，有差异才重绘并提示（避免每次聚焦都闪绘）。 */
  async function refreshEditorAfterExternalChange() {
    const ed = editor;
    if (!ed || ed.saving || ed.changes.size > 0) return;
    const guid = ed.schemeGuid;
    let dumpResp = null;
    try {
      dumpResp = await window.api.syspanel.powerSettingsDump(guid);
    } catch (e) {
      return;
    }
    // 等待期间会话可能已被保存/取消；选中方案也可能已变——不一致就放弃本次刷新
    if (!editor || editor !== ed || !dumpResp || !dumpResp.success) return;
    const dump = dumpResp.data || {};
    const newOrigin = new Map();
    for (const g of dump.subgroups || []) {
      for (const s of g.settings || []) {
        newOrigin.set(pwrKey(s.subgroupGuid, s.guid), { ac: s.valueAc, dc: s.valueDc });
      }
    }
    let changed = newOrigin.size !== ed.origin.size;
    if (!changed) {
      for (const [k, v] of newOrigin) {
        const o = ed.origin.get(k);
        if (!o || o.ac !== v.ac || o.dc !== v.dc) { changed = true; break; }
      }
    }
    if (!changed) return; // 外部没有改动：静默（不重绘、不提示）
    ed.dump = dump;
    ed.origin = newOrigin;
    ed.searchText = new Map();
    ed.compareCache.clear();
    for (const s of (dump.subgroups || []).flatMap((g) => g.settings || [])) {
      const zw = pwrZh(s.guid);
      ed.searchText.set(pwrKey(s.subgroupGuid, s.guid), [
        s.name, zw?.name, s.description, zw?.desc,
      ].filter(Boolean).join(' ').toLowerCase());
    }
    const keepSelected = ed.selectedKey;
    renderEditor();
    // 重绘后恢复选中态（DOM 重建，class 与详情区都要补回）
    if (keepSelected) {
      const node = Array.from(document.querySelectorAll('.syspanel-pwr-item'))
        .find((n) => n.dataset.key === keepSelected);
      if (node) {
        node.classList.add('is-active');
        renderDetail();
      }
    }
    applySearchFilter();
    pwrToast('info', '检测到外部改动，已自动重新读取本方案设置');
  }

  /** 详情区按钮委托（「在注册表中查看」）。 */  async function onDetailClick(ev) {
    const btn = ev.target.closest('#btnSyspanelPwrRegedit');
    if (!btn || !editor) return;
    const s = findSetting(editor.selectedKey);
    if (!s) return;
    btn.disabled = true;
    btn.textContent = '正在打开…';
    try {
      const resp = await window.api.syspanel.powerSettingsOpenRegedit(s.subgroupGuid, s.guid);
      if (resp && resp.success) pwrToast('info', '已打开注册表编辑器并定位到该设置');
      else pwrToast('error', (resp && resp.message) || '打开注册表失败');
    } catch (e) {
      pwrToast('error', '打开注册表异常：' + (e && e.message ? e.message : String(e)));
    } finally {
      if (btn.isConnected) { btn.disabled = false; btn.textContent = '在注册表中查看'; }
    }
  }

  function refreshItemMark(key) {    const s = findSetting(key);
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

  // ==================== Windows 更新三态（2026-10-15 从优化中心迁入）====================
  // 「彻底禁用 / 恢复 / 暂停到日期」三项互斥做法各成一张小卡（快捷指令页同款视觉：
  // 三列网格 + qc-card）。执行链**不另起一套**——点击经 window.optimizer.executeOption
  // 走优化模块的高危红色确认 → 系统还原点 → 备份/记账/读回校验（与优化中心详情弹窗
  // 「立即执行」完全同一条）；本模块只负责入口 UI 与暂停日期选择。
  // 卡片 DOM 由本文件进页时挂进 #page-windows-settings：首屏预算贴着上限，静态 HTML
  // 一个字节都加不起（syspanel.js 是按需加载件，字符串字节不计首屏）。
  const WU_CARDS = [
    {
      id: 'perf_windows_update_off',
      name: '彻底禁用自动更新',
      desc: '高危：安全补丁不再自动送达',
      btn: '禁用',
      icon: '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8 0-1.85.63-3.55 1.69-4.9L16.9 18.31C15.55 19.37 13.85 20 12 20zm6.31-3.1L7.1 5.69C8.45 4.63 10.15 4 12 4c4.41 0 8 3.59 8 8 0 1.85-.63 3.55-1.69 4.9z"/>',
      tip: '写 NoAutoUpdate=1，彻底停止自动检查与安装更新，安全更新将不再自动送达。仅建议在明确知晓风险时使用；只想推迟一段时间请用「暂停」。',
    },
    {
      id: 'perf_wu_enable',
      name: '恢复自动更新',
      desc: '恢复系统默认更新行为',
      btn: '恢复',
      icon: '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>',
      tip: '清除 Trim 写入的暂停键与 NoAutoUpdate 策略，让 Windows 恢复默认的自动检查与安装。只删 Trim 写过的键，没让 Trim 动过的设置一概不碰。',
    },
    {
      id: 'perf_wu_pause',
      name: '暂停更新到指定日期',
      desc: '官方暂停键，到期自动恢复',
      btn: '选日期',
      icon: '<path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/>',
      tip: '写入 Windows 官方暂停键（1~35 天档位），服务照常运行、到期系统自动恢复更新，不停用任何组件。',
    },
  ];

  function initWuSection() {
    const page = document.getElementById('page-windows-settings');
    if (!page || document.getElementById('syspanelWu')) return;
    const sec = document.createElement('div');
    sec.className = 'syspanel-card';
    sec.id = 'syspanelWu';
    sec.innerHTML = `
      <div class="syspanel-card-head">
        <h4>Windows 更新</h4>
        <span class="syspanel-tag">三选一 · 改前自动备份</span>
      </div>
      <div class="qc-grid">
        ${WU_CARDS.map(w => `
        <div class="qc-card" data-tip="${escAttr(w.tip)}">
          <div class="qc-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">${w.icon}</svg></div>
          <div class="qc-body">
            <div class="qc-name">${esc(w.name)}</div>
            <div class="qc-desc">${esc(w.desc)}</div>
          </div>
          <div class="qc-actions">
            <button type="button" class="btn btn-secondary btn-small" data-wu-run="${escAttr(w.id)}">${esc(w.btn)}</button>
          </div>
        </div>`).join('')}
      </div>`;
    page.appendChild(sec);
    // 主窗最小宽 1387px（lib.rs MIN_WIDTH），三列在任何可达宽度下都放得下；
    // 固定三列而非走 .qc-grid 的 4 列断点 —— 三项就该一行三列（对齐 2026-10-11
    // 用户对 qc 网格「列数不许随宽度乱跳」的裁定）。行内样式压过媒体查询，不新增 CSS。
    const grid = sec.querySelector('.qc-grid');
    if (grid) grid.style.gridTemplateColumns = 'repeat(3, 1fr)';
    sec.querySelectorAll('[data-wu-run]').forEach((btn) => {
      // guard：onWuRun 是 async，其内的确认框/日期弹窗任一环 reject 都会变成浮动
      // Promise（v2-M22 同族，用户侧表现为「点击后毫无反应」），统一在此收口。
      btn.addEventListener('click', () => {
        Promise.resolve(onWuRun(btn.dataset.wuRun)).catch((e) => {
          pwrToast('error', 'Windows 更新调整异常：' + ((e && e.message) || e));
        });
      });
    });
  }

  async function onWuRun(id) {
    if (!window.optimizer?.executeOption) {
      pwrToast('warning', '优化组件未加载，请稍后重试');
      return;
    }
    if (id === 'perf_wu_pause') { openWuPausePicker(); return; }
    await window.optimizer.executeOption(id);
  }

  /** 暂停到指定日期：明天起、最长 WU_PAUSE_MAX_DAYS 天（上限与换算取自优化模块导出，不另抄一份） */
  function openWuPausePicker() {
    const O = window.optimizer;
    if (!window.modal?.create || !O) { pwrToast('warning', '当前环境不支持暂停设置'); return; }
    const maxDays = O.WU_PAUSE_MAX_DAYS;
    const ctrl = window.modal.create({
      id: 'syspanelWuPauseModal',
      title: '暂停 Windows 更新',
      bodyHtml: `
        <p class="syspanel-pwr-modal-hint">选择暂停截止日期（明天起、最长 ${maxDays} 天）：到期系统自动恢复更新，期间更新服务照常运行。</p>
        <label class="opt-inline">暂停到
          <input type="date" class="field-input opt-choice-date" id="syspanelWuPauseDate"
            min="${escAttr(O.dateInputValue(1))}" max="${escAttr(O.dateInputValue(maxDays))}" />
        </label>
        <p class="opt-choice-days" id="syspanelWuPauseDays">请选择日期</p>`,
      footerHtml: `
        <button type="button" class="btn btn-secondary" data-modal-cancel>取消</button>
        <button type="button" class="btn btn-primary" data-modal-ok disabled>确认暂停</button>`,
      width: 420,
      initialFocus: '#syspanelWuPauseDate',
    });
    const dateEl = ctrl.body.querySelector('#syspanelWuPauseDate');
    const daysEl = ctrl.body.querySelector('#syspanelWuPauseDays');
    const okBtn = ctrl.footer.querySelector('[data-modal-ok]');
    const sync = () => {
      const days = O.pauseDaysFrom(dateEl?.value);
      okBtn.disabled = days == null;
      daysEl.textContent = days == null
        ? `请选择一个明天以后的日期（最长 ${maxDays} 天）`
        : `共暂停 ${days} 天，到期系统自动恢复更新`;
    };
    dateEl?.addEventListener('input', sync);
    ctrl.footer.querySelector('[data-modal-cancel]').addEventListener('click', () => ctrl.close());
    okBtn.addEventListener('click', () => {
      const days = O.pauseDaysFrom(dateEl?.value);
      if (days == null) return;
      ctrl.close();
      Promise.resolve(O.executeOption('perf_wu_pause', String(days))).catch((e) => {
        pwrToast('error', '暂停更新执行异常：' + ((e && e.message) || e));
      });
    });
    sync();
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
    // v5 P2：窗口重新激活 = 用户可能刚在别的工具里改过设置，节流地自动重读
    window.addEventListener('focus', scheduleAutoRefresh);
    document.addEventListener('visibilitychange', scheduleAutoRefresh);
    // 首帧进 Windows设置 页时拉一次；后续靠"刷新"按钮再拉。
    if (!powerLoaded) {
      loadPower();
    }
    loadPagefile();
    // 「Windows 更新」三态卡（2026-10-15 从优化中心迁入；点击时读 window.optimizer，
    // 由 PAGE_SCRIPTS['windows-settings'] 的加载序保证就位）
    initWuSection();
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
