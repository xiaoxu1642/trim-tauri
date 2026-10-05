// optimizer.js - 优化电脑模块
// 渲染由 optimizer:list 拉取的选项目录为分组胶囊卡片；
// 卡片宽度按窗口自适应：非最大化一行 3 条，最大化一行 6 条；
// 点击卡片弹出详情弹窗（优缺点 + 详细操作 + 执行/还原/AI），背景模糊遮罩；
// 点击空白/遮罩、ESC 键即可关闭弹窗。
// 执行仍通过 main 进程后台静默执行，实时进度以主界面右上角 Toast 展示。
(function () {
  'use strict';

  const RISK_TEXT = { low: '低风险', medium: '中风险', high: '高风险' };

  // ==================== E7：分类两层结构（default / custom）====================
  //
  // 借 Winaero `NavigationPane` 的 `pageNavPaneDefaultItems` 与
  // `pageNavPaneCustomItems` 两层：主序列与逐项覆写分开，别混成一张表。
  //
  // 数据源 = `src-tauri/data/optimizer-groups.json`（E7 侧表），经
  // `optimizer:list-groups` 通道下发。**为什么搬**：分类顺序与重映射规则是**产品口径**，
  // 埋在渲染层里就没法被门禁对拍、也没法在不改前端口径的情况下单独调整。
  //
  // ⚠️ 侧表**刻意不含任何颜色字段** —— GROUP_COLORS（13 条 linear-gradient）与
  // GROUP_ACCENT（13 个 hex）在 M20 已删除，分类列统一吃 `--c` / `--cf` 的 token 兜底。
  // 借这次搬家把它们请回来就是离表色复活，`check-css-tokens` 会红。
  //
  // 兜底语义（**不许削弱**）：侧表缺席/损坏时用下面的 BUILTIN 常量，
  // 它与侧表内容一致 —— 门禁 check-optimizer-groups-sidecar 对拍两侧，
  // 改了一边忘了另一边即红。
  const GROUP_FALLBACK = {
    default: ['内存优化', '性能调优', '音频优化', '外设调优', '桌面体验', '任务调度', '系统服务', '隐私防护', '系统调校', '系统精简', '显卡优化', '浏览器优化'],
    groupMap: {
      '启动与响应': '系统调校',
      '游戏与多媒体': '性能调优',
      '安全与隐私': '隐私防护',
      '系统清理': '系统精简',
      '显卡优化': '显卡优化',
      '键鼠与外设': '外设调优',
      '系统精简': '系统精简'
    },
    itemOverride: {
      svc_mem_gb: '内存优化', tf_mmagent: '内存优化',
      tf_svc_bulk: '系统服务', tf_drv_disable: '系统服务'
    }
  };
  let GROUP_ORDER = GROUP_FALLBACK.default.slice();
  let GROUP_MAP = GROUP_FALLBACK.groupMap;
  let ITEM_GROUP_OVERRIDE = GROUP_FALLBACK.itemOverride;
  let GROUPS_FROM_SIDECAR = false;

  /** 用侧表覆盖内置常量。侧表缺席/形状不对时保留内置（并保持 GROUPS_FROM_SIDECAR=false，
   *  便于门禁/日志区分「走的侧表」还是「走的兜底」）。 */
  function applyGroupSidecar(raw) {
    if (!raw || typeof raw !== 'object') return false;
    const def = raw.default;
    const cus = raw.custom;
    if (!Array.isArray(def) || !def.length) return false;
    if (!cus || typeof cus.groupMap !== 'object' || typeof cus.itemOverride !== 'object') return false;
    GROUP_ORDER = def.slice();
    GROUP_MAP = cus.groupMap;
    ITEM_GROUP_OVERRIDE = cus.itemOverride;
    GROUPS_FROM_SIDECAR = true;
    return true;
  }

  function displayGroup(o) {
    if (ITEM_GROUP_OVERRIDE[o.id]) return ITEM_GROUP_OVERRIDE[o.id];
    return GROUP_MAP[o.group] || o.group;
  }

  const GROUP_ICONS = {
    '系统调校': '<path d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L8.9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.954 8.954 0 0 0 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/>',
    '性能调优': '<path d="M12 2L4 7v10l8 5 8-5V7l-8-5zm0 3.9l5.5 3.44v6.32L12 18.1l-5.5-3.44V8.34L12 5.9zM11 9h2v4h-2V9zm0 5.5h2v2h-2v-2z"/>',
    '内存优化': '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>',
    '隐私防护': '<path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>',
    '显卡优化': '<path d="M21 3H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h5v2h8v-2h5c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 14H3V5h18v12zM7 12h2v2H7v-2zm4 0h2v2h-2v-2zm4 0h2v2h-2v-2z"/>',
    '外设调优': '<path d="M12 2C8.13 2 5 5.13 5 9v1h14V9c0-3.87-3.13-7-7-7zM5 12v2c0 3.87 3.13 7 7 7s7-3.13 7-7v-2H5zm6 6v-3h2v3h-2z"/>',
    '音频优化': '<path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/>',
    '桌面体验': '<path d="M4 4h16c1.1 0 2 .9 2 2v10c0 1.1-.9 2-2 2h-7v2h3c.55 0 1 .45 1 1s-.45 1-1 1H8c-.55 0-1-.45-1-1s.45-1 1-1h3v-2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2zm0 12h16V6H4v10z"/>',
    '任务调度': '<path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z"/>',
    '系统服务': '<path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm4 10.5h-3v3h-2v-3H8v-2h3v-3h2v3h3v2z"/>',
    '系统精简': '<path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14zM8 9h8V7H8v2zm0 4h8v-2H8v2zm0 4h6v-2H8v2z"/>',
    '浏览器优化': '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>'
  };
  // 审查 M20：原先这里有 GROUP_COLORS（13 条 linear-gradient）与 GROUP_ACCENT（13 个 hex），
  // 前者全仓零引用（死表），后者的色值 13 个里 13 个在 main.css 找不到对应 token ——
  // 直撞 AGENTS §2「禁彩色渐变」「只用 main.css 既有 token」。
  // 分类列现在统一吃 `--c` 的 CSS 兜底（var(--accent)）与 .opt-detail-icon 的 token 底色，
  // 分类靠标题与图标区分，不靠彩虹。

  const GEAR_ICON = '<path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>';

  const MEMORY_OPTIONS = [
    { gb: 4, label: '4 GB' }, { gb: 8, label: '8 GB' }, { gb: 12, label: '12 GB' },
    { gb: 16, label: '16 GB' }, { gb: 24, label: '24 GB' }, { gb: 32, label: '32 GB' },
    { gb: 'default', label: '重置为默认' }
  ];

  // SVCHost 内存阈值各档位的优/缺点描述（随下拉联动刷新）
  const MEM_PROS_CONS = {
    4: {
      pros: '4GB 小内存机器推荐提高阈值，显著减少 svchost 进程数量，降低内存碎片与上下文切换开销。',
      cons: '阈值过高可能导致单个 svchost 承载服务过多，单点故障影响面扩大。'
    },
    8: {
      pros: '8GB 内存档位的常用折中值，减少服务进程数的同时保持服务隔离性。',
      cons: '对 8GB 以上机器改善有限；服务过多时仍可能出现单进程负载偏高。'
    },
    12: {
      pros: '12GB 内存档位：进一步减少 svchost 进程数，降低系统总体内存占用。',
      cons: '阈值偏大时服务隔离性下降，个别服务异常可能牵连同组服务。'
    },
    16: {
      pros: '16GB 大内存机器上减少 svchost 进程数量，降低调度与内存管理开销。',
      cons: '大内存下 svchost 拆分本身的开销占比已不高，收益相对有限。'
    },
    24: {
      pros: '24GB 以上大内存减少进程数与调度开销，适合以稳定运行为主的工作站。',
      cons: '服务隔离性减弱，调试单个服务问题时难度上升。'
    },
    32: {
      pros: '32GB 及以上内存最大化合并 svchost 进程，降低内存管理与上下文切换开销。',
      cons: '服务合并程度最高，单点故障影响面最大，不推荐对稳定性要求极高的生产环境使用。'
    },
    default: {
      pros: '恢复 Windows 默认拆分阈值，保持微软推荐的服务隔离级别与稳定性。',
      cons: 'svchost 进程数较多，小内存机器上内存碎片与调度开销相对明显。'
    }
  };

  // ==================== dynamic 项的「控件 + 参数」分派表（审查 v2-M10）====================
  // 根因：后端 is_dynamic 分支只认两个 id，而**两者要求的参数不同** ——
  //   svc_mem_gb 取 p.gb（缺失时按 8GB 兜底，仍是成功）、perf_wu_pause 取 p.days
  //   （缺失直接 return「缺少暂停天数参数」，见 optimizer.rs 的 is_dynamic 段）。
  // 前端此前对 `dynamic` 一刀切：一律画 MEMORY_OPTIONS 的 GB 下拉、一律只发 {gb}，
  // 于是「Windows 更新：暂停到日期」在界面上可见可点、后端永远收不到 days ⇒ 该项 100% 执行失败，
  // 弹窗文案还写着「SVCHost 拆分阈值」。这类错**不报错、不崩溃**，只表现为「这个优化项永远失败」。
  // 约束（新增 dynamic 项时逐条对齐）：
  //   1. 必须在本表登记，key 用数据层 id；
  //   2. `paramKey` 与 Rust 读的结构体字段名**逐字相同**（嵌套结构体没有 camelCase 自动转换，AGENTS §5.4）；
  //   3. 上限值要与 Rust 常量一致（WU_PAUSE_MAX_DAYS）。
  // 三份集合（数据层 dynamic 项 ⇄ 本表 ⇄ Rust 分支）由 tools/check-optimizer-dynamic.mjs 静态对拍钉住。
  const WU_PAUSE_MAX_DAYS = 35; // 与 optimizer.rs 的 WU_PAUSE_MAX_DAYS 对齐，改一处必须同步

  const DYNAMIC_CONTROLS = {
    svc_mem_gb: {
      paramKey: 'gb',
      tip: '选择内存大小或重置',
      defaultValue: '8',
      options: MEMORY_OPTIONS.map((m) => ({ value: String(m.gb), label: m.label })),
      // 'default' 必须原样透传：Rust 按字符串认这一档。旧实现是 `Number(sel.value) || 8`，
      // 把 'default' 变成 NaN→8 —— 「重置为默认」实际写入 8GB 阈值（同源缺陷，顺手随本表修掉）。
      parse: (v) => (v === 'default' ? 'default' : (Number(v) || 8)),
      stepLabel: (v) => 'SVCHost 拆分阈值 ' + (v === 'default' ? '重置为默认值' : v + ' GB'),
      stepNote: () => 'reg add HKLM\\SYSTEM\\ControlSet001\\Control /v SvcHostSplitThresholdInKB /t REG_DWORD /d … /f',
      prosCons: (v) => MEM_PROS_CONS[v] || MEM_PROS_CONS[8]
    },
    perf_wu_pause: {
      paramKey: 'days',
      tip: '选择暂停天数（1~35 天，走官方暂停键，到期自动恢复）',
      defaultValue: '7',
      options: Array.from({ length: WU_PAUSE_MAX_DAYS }, (_, i) => ({
        value: String(i + 1), label: '暂停 ' + (i + 1) + ' 天'
      })),
      // 钳到 1~35：后端也会 clamp（wu_pause_steps），前端先钳是为了「界面显示的档位＝真正写入的档位」
      parse: (v) => Math.min(WU_PAUSE_MAX_DAYS, Math.max(1, Math.trunc(Number(v)) || 1)),
      stepLabel: (v) => 'Windows 更新暂停 ' + v + ' 天',
      stepNote: () => 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate 的 Pause*Updates 起止时间（UTC FILETIME，到期系统自动恢复）',
      prosCons: null // 该项优缺点取数据层 desc/pros/cons，不随天数变化
    }
  };

  // 纯函数（供 tools/check-optimizer-dynamic.mjs 与人工核对使用）：
  // 原始下拉文本 → 后端参数对象。未登记的 id 返回 null，**调用方必须显式处理**，
  // 不许静默退回 {}（那正是 v2-M10 的失法形态：参数没给、后端报错、界面看不出来）。
  function dynamicParams(optId, rawValue) {
    const c = Object.prototype.hasOwnProperty.call(DYNAMIC_CONTROLS, optId) ? DYNAMIC_CONTROLS[optId] : null;
    if (!c) return null;
    const raw = (rawValue === undefined || rawValue === null || rawValue === '') ? c.defaultValue : rawValue;
    return { [c.paramKey]: c.parse(raw) };
  }

  // ==================== 虚拟合集卡（前端聚合，数据层不动）====================
  // 为什么不在数据层合成一项：三态各有独立的 steps / restore / 备份记账与后端执行分支
  // （perf_windows_update_off 写 NoAutoUpdate、perf_wu_pause 走 is_dynamic 的 days 分支、
  // perf_wu_enable 清键）。塞进同一个 id 等于把三套协议并到一条通道上，而数据层与 vendor
  // 基线是逐字段对拍的双源（check-data-parity P2），分叉的代价远大于列表里少一张卡。
  // 这里只做「一张卡 → 用户先选哪一态 → 派发到原 id」，原 id 的备份、还原与账本全部照旧。
  const VIRTUAL_GROUPS = {
    wu_adjust: {
      id: 'wu_adjust',
      title: 'Windows更新调整',
      group: '性能调优',
      risk: 'high', // 三态里含「彻底禁用」，卡片按最高档标注；红色确认按**选中的那一态**判
      desc: '把「彻底禁用 / 恢复自动更新 / 推迟一段时间」三种互斥做法收在一张卡里。三者不能同时成立，所以点开必须先选一种，不替你决定更新策略。',
      choices: [
        { runId: 'perf_windows_update_off', name: '彻底禁用自动更新', desc: '写 NoAutoUpdate=1，安全补丁不再自动送达；仅在明确知晓风险时使用。', state: '高危' },
        { runId: 'perf_wu_enable', name: '恢复自动更新', desc: '只清 Trim 写过的暂停键与 NoAutoUpdate 策略，没让 Trim 动过的设置一概不碰。' },
        { runId: 'perf_wu_pause', name: '暂停更新到指定日期', desc: '走 Windows 官方暂停键，到期系统自动恢复，不停用任何组件。', needsDate: true }
      ]
    }
  };
  const VIRTUAL_RUN_IDS = new Set(
    Object.keys(VIRTUAL_GROUPS).reduce((acc, k) => acc.concat(VIRTUAL_GROUPS[k].choices.map(c => c.runId)), [])
  );

  function virtualOf(id) { return Object.prototype.hasOwnProperty.call(VIRTUAL_GROUPS, id) ? VIRTUAL_GROUPS[id] : null; }

  /** 列表视图：被聚合的真实项从清单里摘掉，虚拟卡插到它首个成员原来所在的位置 */
  function displayList(options) {
    const out = [];
    for (const o of options) {
      if (VIRTUAL_RUN_IDS.has(o.id)) {
        const g = virtualOfByRunId(o.id);
        if (g && out.indexOf(g) < 0) out.push(g);
        continue;
      }
      out.push(o);
    }
    return out;
  }
  function virtualOfByRunId(runId) {
    const keys = Object.keys(VIRTUAL_GROUPS);
    for (const k of keys) if (VIRTUAL_GROUPS[k].choices.some(c => c.runId === runId)) return VIRTUAL_GROUPS[k];
    return null;
  }
  /** 行 id → 条目（虚拟卡不在 OPTIONS 里，点击/批量都要认得它） */
  function findEntry(id) { return virtualOf(id) || OPTIONS.find(o => o.id === id) || null; }
  /** 需要用户先做选择的条目：dynamic（后端要参数）与虚拟多态卡（三态互斥） */
  function needsUserChoice(entry) { return !!virtualOf(entry.id) || !!entry.dynamic; }

  // 「暂停到 xx 年 xx 月 xx 日」→ 后端协议要的 days。上限只在 WU_PAUSE_MAX_DAYS 一处持有
  // （与 Rust 同值，由 check-optimizer-dynamic A4 对拍钉住），这里不另写第二份数字。
  function pauseDaysFrom(dateStr) {
    if (!dateStr) return null;
    const t = new Date(dateStr + 'T00:00:00').getTime();
    if (!isFinite(t)) return null;
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const days = Math.round((t - today.getTime()) / 86400000);
    return days >= 1 ? Math.min(WU_PAUSE_MAX_DAYS, days) : null;
  }
  function dateInputValue(offsetDays) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() + offsetDays);
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }

  // 单个条目当前选中的执行参数；返回 null = 还没选完（确认按钮据此保持禁用）
  function draftParamsFor(entryId, state) {
    const s = state.get(entryId);
    if (!s || !s.runId) return null;
    const g = virtualOf(entryId);
    if (g) {
      const c = g.choices.find(x => x.runId === s.runId);
      if (!c) return null;
      if (c.needsDate) {
        const days = pauseDaysFrom(s.date);
        if (days == null) return null;
        return { runId: c.runId, params: dynamicParams('perf_wu_pause', String(days)), label: '暂停 ' + days + ' 天' };
      }
      return { runId: c.runId, params: {}, label: c.name };
    }
    const ctl = DYNAMIC_CONTROLS[entryId];
    if (ctl) {
      if (s.value === undefined || s.value === null || s.value === '') return null;
      return { runId: entryId, params: dynamicParams(entryId, s.value), label: String(s.value) };
    }
    return { runId: entryId, params: {}, label: '' };
  }

  function choiceGroupHtml(entry) {
    const g = virtualOf(entry.id);
    if (g) {
      const rows = g.choices.map(c => `
        <label class="model-picker-item" data-choice-row>
          <input type="radio" name="optChoice_${window.ds.escAttr(g.id)}" value="${window.ds.escAttr(c.runId)}" />
          <span class="model-picker-radio"></span>
          <span class="model-picker-copy">
            <span class="model-picker-name">${escapeHtml(c.name)}</span>
            <span class="model-picker-desc">${escapeHtml(c.desc)}</span>
          </span>
          ${c.state ? `<span class="model-picker-state warn">${escapeHtml(c.state)}</span>` : ''}
        </label>`).join('');
      return `
        <div class="opt-choice-group" data-choice-for="${window.ds.escAttr(g.id)}">
          <div class="opt-choice-title">${escapeHtml(g.title)}</div>
          <div class="opt-choice-desc">${escapeHtml(g.desc)}</div>
          <div class="model-picker-list">${rows}
            <div class="opt-choice-extra" data-choice-date-for="${window.ds.escAttr(g.id)}" hidden>
              <label class="opt-inline">暂停到
                <input type="date" class="field-input opt-choice-date" data-choice-date="${window.ds.escAttr(g.id)}"
                  min="${window.ds.escAttr(dateInputValue(1))}" max="${window.ds.escAttr(dateInputValue(WU_PAUSE_MAX_DAYS))}" />
              </label>
              <span class="opt-choice-days" data-choice-days="${window.ds.escAttr(g.id)}">可选区间：明天起，最多 ${WU_PAUSE_MAX_DAYS} 天</span>
            </div>
          </div>
        </div>`;
    }
    // dynamic 真实项：档位一律取自 DYNAMIC_CONTROLS，不在此另写一份选项
    const ctl = DYNAMIC_CONTROLS[entry.id];
    const rows2 = (ctl ? ctl.options : []).map(o => `
        <label class="model-picker-item" data-choice-row>
          <input type="radio" name="optChoice_${window.ds.escAttr(entry.id)}" value="${window.ds.escAttr(o.value)}" />
          <span class="model-picker-radio"></span>
          <span class="model-picker-copy"><span class="model-picker-name">${escapeHtml(o.label)}</span></span>
        </label>`).join('');
    return `
      <div class="opt-choice-group" data-choice-for="${window.ds.escAttr(entry.id)}">
        <div class="opt-choice-title">${escapeHtml(entry.title)}</div>
        <div class="opt-choice-desc">${escapeHtml(ctl ? ctl.tip : '该项需要指定参数后才能执行。')}</div>
        <div class="model-picker-list">${rows2}</div>
      </div>`;
  }

  // 自绘选择窗：单项执行（点开虚拟卡）与批量执行（勾到多态 / dynamic 项）共用一份实现。
  // 返回 Promise<Map<runId, params>>；用户取消 / Esc / 点遮罩一律 resolve null，
  // 调用方必须中止整批 —— 退回到 defaultValue 就是「替用户做选择」（2026-09-30 用户裁定）。
  function promptUserChoices(entries) {
    return new Promise((resolve) => {
      const state = new Map();      // entryId -> { runId, date, value }
      let settled = false;
      const finish = (v) => { if (!settled) { settled = true; resolve(v); } };
      const g0 = virtualOf(entries[0].id);
      const ctrl = window.modal.create({
        id: 'optChoiceModal-' + Date.now(),
        title: entries.length > 1 ? '请先选择做法' : (g0 ? g0.title : entries[0].title),
        iconSvg: `<span class="opt-detail-icon"><svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor">${GEAR_ICON}</svg></span>`,
        bodyHtml: `<div class="opt-choice-body">${entries.map(choiceGroupHtml).join('')}</div>`,
        footerHtml: `
          <span class="opt-choice-hint" data-role="hint">每一项都要选定一个做法才能继续。</span>
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary" data-role="cancelBtn" type="button">取消</button>
          <button class="btn btn-primary" data-role="okBtn" type="button" disabled>确认选择</button>`,
        bodyClass: 'opt-choice-modal-body',
        onClose: () => finish(null)
      });
      const okBtn = ctrl.footer.querySelector('[data-role="okBtn"]');
      const hintEl = ctrl.footer.querySelector('[data-role="hint"]');

      function sync() {
        const resolved = new Map();
        let missing = null;
        for (const e of entries) {
          const p = draftParamsFor(e.id, state);
          if (!p) { missing = e; break; }
          resolved.set(p.runId, p.params);
        }
        okBtn.disabled = !!missing;
        hintEl.textContent = missing
          ? `还差「${missing.title || (virtualOf(missing.id) || {}).title || missing.id}」的做法没选。`
          : `将执行：${entries.map(e => { const p = draftParamsFor(e.id, state); const real = OPTIONS.find(o => o.id === p.runId); return real ? real.title : p.runId; }).join('、')}`;
        return resolved;
      }

      ctrl.body.addEventListener('change', (e) => {
        const group = e.target.closest('[data-choice-for]');
        if (!group) return;
        const entryId = group.dataset.choiceFor;
        const radio = e.target.closest('input[type="radio"]');
        if (radio) {
          const cur = state.get(entryId) || {};
          // 两类条目的 radio.value 语义不同：虚拟卡是「选哪一态」（runId），
          // dynamic 项是「取哪个档位」（runId 就是它自己）。混存会让档位被当成 id，
          // draftParamsFor 永远判未选完 → 批量选择窗的确认按钮点不动。
          state.set(entryId, virtualOf(entryId)
            ? Object.assign({}, cur, { runId: radio.value })
            : Object.assign({}, cur, { runId: entryId, value: radio.value }));
          group.querySelectorAll('[data-choice-row]').forEach(l =>
            l.classList.toggle('active', l.querySelector('input').checked));
          const extra = group.querySelector('[data-choice-date-for]');
          if (extra) {
            const c = (virtualOf(entryId) || { choices: [] }).choices.find(x => x.runId === radio.value);
            extra.hidden = !(c && c.needsDate);
          }
        }
        const dateEl = e.target.closest('input[type="date"]');
        if (dateEl) {
          const cur = state.get(entryId) || {};
          state.set(entryId, Object.assign({}, cur, { date: dateEl.value }));
          const daysEl = group.querySelector('[data-choice-days]');
          const days = pauseDaysFrom(dateEl.value);
          if (daysEl) daysEl.textContent = days == null ? '请选择一个明天以后的日期' : `共暂停 ${days} 天，到期系统自动恢复更新`;
        }
        sync();
      });
      okBtn.addEventListener('click', () => {
        const resolved = sync();
        if (!resolved || okBtn.disabled) return;
        settled = true;              // 选定：让 onClose 不再把结果覆盖成 null
        ctrl.close();
        finish(resolved);
      });
      ctrl.footer.querySelector('[data-role="cancelBtn"]').addEventListener('click', () => ctrl.close());
    });
  }

  /** 条目清单 → 真实执行清单（虚拟卡换成用户选中的那个真实项） */
  function expandEntries(entries, paramsByRun) {
    const out = [];
    for (const e of entries) {
      const g = virtualOf(e.id);
      if (!g) { out.push(e); continue; }
      const runId = chosenRunOf(g, paramsByRun);
      const real = runId ? OPTIONS.find(o => o.id === runId) : null;
      if (real) out.push(real);
    }
    return out;
  }
  // paramsByRun 的键就是 runId，反查该虚拟卡被选中的那一态（同一卡只会命中一个）
  function chosenRunOf(g, paramsByRun) {
    const hit = g.choices.map(c => c.runId).filter(id => paramsByRun.has(id));
    return hit.length ? hit[0] : null;
  }

  /** 用户选定某一态后按真实项执行：确认链与单项「立即执行」完全同一条（不另起一套） */
  async function runChosenEntry(runId, params) {
    const real = OPTIONS.find(o => o.id === runId);
    if (!real) {
      window.app?.toast('error', `所选做法（${runId}）不在优化目录里，已中止`);
      window.app?.log?.('error', `优化虚拟项派发失败：目录里找不到 ${runId}`);
      return;
    }
    // 三态里只有「彻底禁用」是高危，红色确认按**选中的那一态**判，不按整卡标注的档位判
    if (!(await confirmHazard(real))) return;
    if (!(await ensureRestorePoint())) return;
    try {
      await runOptionActive(params, real);
    } catch (e) {
      window.app?.toast('error', '优化执行失败: ' + (e.message || e));
    }
  }

  async function openVirtualChoice(g) {
    const paramsByRun = await promptUserChoices([g]);
    if (!paramsByRun) return;            // 取消 / Esc / 点遮罩：什么都不做，不退回默认那一态
    const runId = chosenRunOf(g, paramsByRun);
    if (runId) await runChosenEntry(runId, paramsByRun.get(runId));
  }

  // ==================== 进度型 Toast ====================
  // v3.7.0 议题一（单例语义修复）：此前的实现有两个相互叠加的缺陷——
  //   ① finishProgressToast 先把模块级 progressToast 置空，已完成的那条就此脱离
  //      单例管理变成孤儿，后续 disposeProgressToast 因 `if (!progressToast) return` 空转；
  //   ② 移除计时器挂在模块级 progressTimer 上，下一条完成时 clearTimeout 会顺手
  //      取消掉上一条的计时 → 批量 N 项时前 N-1 条永久驻留（与截图一堆积形态吻合）。
  // 现在：完成只打 finished 标记不摘引用，计时器归属 Toast 自身（t.removeTimer），
  // 由下一条 createProgressToast 认领槽位时统一清理上一条。
  let progressToast = null;
  const PROGRESS_TOAST_DWELL_MS = 2000; // 单条完成后停留 2s（2026-09-23 用户裁定口径）
  // 批量执行时的序号后缀（「3/12」）。此前循环里先建一条带序号的 Toast，runOptionActive
  // 内又建一条并立刻销毁前者——每项白建白毁一个节点；现在只建一条，序号走这个后缀传入。
  let progressToastSuffix = '';

  function iconFor(type) {
    if (type === 'success') return '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>';
    if (type === 'error') return '<path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.48 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"/>';
    return GEAR_ICON;
  }

  function createProgressToast(title) {
    const container = document.getElementById('toastContainer');
    if (!container) return null;
    disposeProgressToast(true);
    const el = document.createElement('div');
    el.className = 'toast info toast-progress';
    el.innerHTML = `
      <div class="toast-icon">${iconFor('pending')}</div>
      <div class="toast-message">
        <div class="toast-title">优化电脑${progressToastSuffix ? '（' + progressToastSuffix + '）' : ''}</div>
        <div class="toast-tune">正在执行「${title}」…</div>
        <div class="toast-progress"><div class="toast-progress-bar"><div class="toast-progress-fill"></div></div></div>
      </div>`;
    container.appendChild(el);
    const entry = {
      el,
      title,
      finished: false,
      removeTimer: null,
      // 让「点击空白关最顶层 Toast」也够得到进度 Toast（此前它游离在 activeToasts 之外）
      remove: () => disposeProgressToast(true)
    };
    progressToast = entry;
    window.app?.registerToast?.(entry);
    return progressToast;
  }

  function setProgressToastProgress(pct) {
    if (!progressToast) return;
    const fill = progressToast.el.querySelector('.toast-progress-fill');
    const tune = progressToast.el.querySelector('.toast-tune');
    if (fill) fill.style.width = pct + '%';
    if (tune) tune.textContent = `执行中 ${pct}%（${progressToast.title}）`;
  }

  function finishProgressToast(ok, message) {
    if (!progressToast) return;
    const t = progressToast;
    // 不再提前摘引用：保留 finished 标记，由下一条 createProgressToast 或计时器回收
    t.finished = true;
    const icon = t.el.querySelector('.toast-icon');
    const tune = t.el.querySelector('.toast-tune');
    if (icon) icon.innerHTML = ok ? iconFor('success') : iconFor('error');
    if (tune) tune.textContent = ok ? '设置已生效 — ' + t.title : (message || '执行失败');
    const fill = t.el.querySelector('.toast-progress-fill');
    if (fill) { fill.style.width = '100%'; fill.classList.add(ok ? 'done' : 'failed'); }
    t.el.classList.remove('info');
    t.el.classList.add(ok ? 'success' : 'error');
    clearTimeout(t.removeTimer);
    // 计时器归属自身：不再存在"下一条取消上一条计时"的连带取消
    t.removeTimer = setTimeout(() => disposeProgressToast(false), PROGRESS_TOAST_DWELL_MS);
  }

  function disposeProgressToast(instant) {
    if (!progressToast) return;
    const t = progressToast;
    progressToast = null;
    clearTimeout(t.removeTimer);
    window.app?.unregisterToast?.(t);
    if (t.el && t.el.parentNode) {
      t.el.classList.add('removing');
      // v3.5.1 动效审查 H4：出场动画 220ms，200ms 移除会把尾巴硬切，留 260ms 余量
      setTimeout(() => t.el && t.el.parentNode && t.el.remove(), instant ? 0 : 260);
    }
  }

  // ==================== 高危项红色警告（合规强化） ====================
  // 以下项会显著削弱系统安全防护，执行前必须弹红色警示确认。
  // 审查 v2-K3：这份手写清单的定位是「比数据层 risk=high 更严的例外集」，通用判据见
  // needsHazardConfirm()。原有的 tf_microcode_del / spectre_off 在 116 项数据里不存在
  // （死条目，只会让这份清单看起来「已核对」），已删；集合差由 check-channel-map 门禁 F
  // 的三条对拍（Rust ⇄ JS ⇄ 数据层 risk=high）钉住，双向差集非空即红。
  const HAZARD_OPTION_IDS = new Set([
    'disable_uac',           // 禁用 UAC
    'tf_defender',           // 关闭 Defender 与 SmartScreen
    'perf_vbs_off',          // 关闭 VBS / 内存完整性
    'perf_exploit_protection_off', // 关闭 Exploit Protection（乱序内存）
    'tf_svc_bulk',           // 禁用 70+ 非必要服务（含安全服务）
    'tf_drv_disable',        // 禁用高风险驱动服务
    'perf_windows_update_off' // v3.7.0 P1：彻底禁用 Windows 更新（安全补丁不再送达）
  ]);

  // ==================== R0-c 服务启动类型修复入口 ====================
  // v0.5.0 的 `svc_*_manual` 四项在执行链里只做了 `sc stop`（startType 字段从未被读取），
  // 于是「服务被停、启动类型仍是 Automatic」，而数据层 label/desc 都写着
  // 「不立即停止」「当前运行不受影响」。R0-a 已修好执行链（只改启动类型、不停服）。
  //
  // 但**存量受害者**（在 v0.5.0 期间点过这四项的用户）机器上服务仍处于被 stop 状态，
  // 而检测侧判「未生效」⇒ 这四项**不会**进灰态 ⇒ 用户点开详情看到的是
  // 「立即执行」而不是「立即恢复」，没有任何入口告诉他「你机器上的服务被停了」。
  //
  // 所以这里给一个**显式**修复入口：只对这四项显示，点击走已有的 `restoreOption`
  // （预置 restore 步骤 = startType 'automatic'，R0-a 已让它真正生效）。
  //
  // 为什么是显式按钮而不是自动修：自动改系统状态而不问用户，就是本仓 §3 红线里
  // 「绝不静默改机器」。按钮只在用户点开这一项的详情时出现，不主动弹。
  const START_TYPE_REPAIR_IDS = new Set([
    'svc_w32time_manual',
    'svc_fdrespum_manual',
    'svc_storsvc_manual',
    'svc_xblauthmgr_manual'
  ]);

  /** 该项是否需要「修复服务启动类型」入口（仅这四项，且必须能还原） */
  function needsStartTypeRepair(opt) {
    if (!START_TYPE_REPAIR_IDS.has(opt.id)) return false;
    // 必须有可用的 restore 步骤，否则按钮会指向一个空操作
    return Array.isArray(opt.restore) && opt.restore.length > 0;
  }

  // 判据集合必须与 Rust 侧 needs_high_risk_confirm 完全一致：手写清单 **或** 数据层自认 high。
  // 三个调用点（confirmHazard / 回执标记 / 批量预览）都得走它——只改确认不改「是否发回执」，
  // 等于后端开始要回执而前端不给，那 7 项会被静默锁死。
  function needsHazardConfirm(opt) {
    return HAZARD_OPTION_IDS.has(opt.id) || opt.risk === 'high';
  }

  // 执行前高危确认：返回 true 继续 / false 取消
  async function confirmHazard(opt) {
    if (!needsHazardConfirm(opt)) return true;
    // R2（RAINZ 对标）：侧表给出了「具体降哪一面」就逐条点名。泛泛的「会降低安全防护」
    // 很容易被点过去；「关闭 UAC」或者「关闭 VBS 与内存完整性」这种具名后果，用户才能真的判断。
    // 文案来源是后端侧表（optimizer-security.json 的 why），不在前端另写一份。
    const sd = opt.securityDegrade;
    const detail = sd && sd.why ? `\n\n本项具体降低的是：\n· ${sd.why}` : '';
    // 红色二次确认：警示文案走 dangerHint 结构化字段，由弹窗模板渲染
    return window.app.confirmDanger(
      '⚠️ 高危安全操作确认',
      `「${opt.title}」会显著降低系统安全防护：\n\n· ${opt.desc || ''}${detail}`,
      '仍然执行',
      '取消',
      '此操作可能使系统更容易受到恶意软件或攻击的侵害，请确认已了解风险。'
    );
  }

  // ==================== 工具 ====================
  function escapeHtml(s) { return window.ds.esc(s); }
  // ⚠️ 属性位转义**刻意不建本地包装**，直接调 window.ds.escAttr（AGENTS §2：
  // 「新代码禁止再定义本地 escapeHtml/escapeAttr」；check-escape-delegation 的
  // 总数棘轮也只许递减）。
  //
  // 这里曾经**既没有包装也没有调用方定义** —— 逐项勾选弹窗在拼 data-pick 属性时
  // 调了 escapeAttr(...)，IIFE + 'use strict' 下那是 ReferenceError，且异常发生在
  // `bodyHtml` 构造阶段（早于 modal.create），于是「点立即执行」表现为
  // **详情弹窗已关、勾选框没出现、什么提示都没有**。
  // 证据：%APPDATA%\com.xiaoxu.trim\logs\app-2026-10-04.log 里两条
  // 「渲染层未处理的 Promise 拒绝：escapeAttr is not defined」。
  // 回归网见 optimizer/contract_tests.rs 的「渲染层转义函数必须都能解析到定义」。

  /**
   * 这一项有没有「逐项选择」界面。
   *
   * ⚠️ 必须**单一判据**：入口条显隐（详情弹窗）与「点立即执行时要不要弹勾选框」
   * （runBtn）以前各写一遍 `o.subitems && …items.length`。两处一旦漂移，症状是
   * 「界面上根本没有逐项选择入口，但点执行会弹一个空勾选框」或反过来 ——
   * 前者用户以为功能没有，后者以为界面坏了。合成一个函数后无漂移可言。
   */
  function hasSubitemPick(o) {
    return !!(o && o.subitems && Array.isArray(o.subitems.items) && o.subitems.items.length);
  }

  /**
   * 逐项选择独立弹窗（2026-10-03 用户裁定形态：点「立即执行」后弹出，不内嵌在详情里）。
   *
   * 为什么从详情弹窗搬出来：内嵌版那个区块在详情弹窗**下方**，要滚动才看得到，
   * 用户反馈「点击执行出现弹窗可选择每一项的页面也没有出现」—— 它确实存在，
   * 只是长得像不存在。而且内嵌时详情弹窗必须一直开着，于是和高危确认框
   * 叠在 DOM 里互相抢 z 序与焦点，表现为「确认框一闪而过」（见 runBtn 处注释）。
   *
   * 返回 Promise<{targets,extras} | null>：null = 用户取消（调用方据此中止执行）。
   *
   * `pre` 是从详情弹窗里读出的初值快照（打开这个弹窗时详情已关，但勾选状态
   * 要延续用户在详情里已经调过的那份，而不是每次重置回全选）。
   */
  function confirmSubitemPick(opt, pre) {
    const items = opt.subitems.items || [];
    const extras = Array.isArray(opt.subitems.extras) ? opt.subitems.extras : [];
    const label = opt.subitems.label || '逐项选择';
    const un = Number(opt.subitems.unexplained) || 0;
    const hint = (opt.subitems.hint || '') + (un > 0 ? `（另有 ${un} 个目标未单独列出说明，全选时仍会执行。）` : '');

    // 顶部摘要条：让用户先看到「这一步到底要动多少东西」，再看清单。
    const targets = new Set(pre.targets);
    const pickedExtras = new Set(pre.extras);

    // 自绘勾选框的三个必备属性（AGENTS §2）：`role=checkbox` 让辅助技术读得出这是勾选框、
    // `tabindex="0"` 让它可聚焦、`aria-checked` 让状态可读。三者缺一，键盘用户
    // 就既看不到也摸不到这个控件 —— 而本清单动辄 70 项，鼠标逐个点是主要交互方式。
    const rowHtml = (it) => `
      <label class="pick-row">
        <span class="checkbox pick-box${targets.has(it.value) ? ' checked' : ''}" role="checkbox" tabindex="0"
              aria-checked="${targets.has(it.value) ? 'true' : 'false'}"
              data-pick="${window.ds.escAttr(it.value)}"></span>
        <span class="pick-name">${escapeHtml(it.value)}</span>
        <span class="pick-note">${escapeHtml(it.note)}</span>
      </label>`;
    const extraHtml = extras.map(ex => `
      <label class="pick-row pick-row-extra">
        <span class="checkbox pick-extra-box${pickedExtras.has(ex.id) ? ' checked' : ''}" role="checkbox" tabindex="0"
              aria-checked="${pickedExtras.has(ex.id) ? 'true' : 'false'}"
              data-pick-extra="${window.ds.escAttr(ex.id)}"></span>
        <span class="pick-name">${escapeHtml(ex.label)}</span>
        <span class="pick-note">${escapeHtml(ex.note)}</span>
      </label>`).join('');

    const bodyHtml = `
      <div class="pick-summary">
        <span class="pick-summary-num" data-pick-count></span>
        <span class="pick-summary-hint">${escapeHtml(hint)}</span>
      </div>
      <div class="pick-toolbar">
        <button class="btn btn-secondary btn-small" type="button" data-pick-all>全选</button>
        <button class="btn btn-secondary btn-small" type="button" data-pick-none>全不选</button>
        <button class="btn btn-secondary btn-small" type="button" data-pick-invert>反选</button>
      </div>
      <div class="pick-list">${items.map(rowHtml).join('')}</div>
      ${extras.length ? `<div class="pick-extras"><div class="pick-extras-title">附带操作（默认不执行）</div>${extraHtml}</div>` : ''}`;

    return new Promise(resolve => {
      let settled = false;
      const finish = v => { if (!settled) { settled = true; resolve(v); } };
      const all = items.map(it => it.value);
      const ctrl = window.modal.create({
        id: 'subitemPick-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6),
        title: label,
        bodyHtml,
        bodyClass: 'pick-body',
        footerHtml: `
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary" data-pick-cancel type="button">取消</button>
          <button class="btn btn-primary" data-pick-ok type="button">按此勾选执行</button>`,
        initialFocus: '[data-pick-ok]',
        onClose() { finish(null); }
      });

      const $ = (s) => ctrl.modal.querySelector(s);
      const counter = $('[data-pick-count]');
      // 分母用后端下发的**清单实数**（`subitems.total`），不是可勾选行数：
      // 未登记解释的目标不在列表里，但全选路径照样会执行到它们 ——
      // 分母写成可勾选行数会让界面上的总数小于真实受影响目标数。
      const totalCount = Number(opt.subitems.total) || all.length;
      const syncCount = () => {
        const tail = extras.length
          ? `，附带操作 ${pickedExtras.size} / ${extras.length} 项`
          : '';
        counter.textContent = `将执行 ${targets.size} / ${totalCount} 项${tail}`;
        // 全不选时禁用确认按钮：让「至少选一项」在按钮态上就说清楚，
        // 而不是点了才 toast 一句又什么都不发生。
        $('[data-pick-ok]').disabled = targets.size === 0;
      };
      // 勾选态回写三处（class / aria-checked / 集合）——只改 class 的话屏幕阅读器
      // 读到的永远是「未勾选」，用户会以为自己没点上而反复点。
      const setTarget = (box, v, on) => {
        if (on) targets.add(v); else targets.delete(v);
        box.classList.toggle('checked', on);
        box.setAttribute('aria-checked', on ? 'true' : 'false');
      };
      const setExtra = (box, id, on) => {
        if (on) pickedExtras.add(id); else pickedExtras.delete(id);
        box.classList.toggle('checked', on);
        box.setAttribute('aria-checked', on ? 'true' : 'false');
      };
      const paint = () => {
        ctrl.modal.querySelectorAll('.pick-box').forEach(b => setTarget(b, b.dataset.pick, targets.has(b.dataset.pick)));
        ctrl.modal.querySelectorAll('.pick-extra-box').forEach(b => setExtra(b, b.dataset.pickExtra, pickedExtras.has(b.dataset.pickExtra)));
        syncCount();
      };

      $('[data-pick-all]').addEventListener('click', () => { targets.clear(); all.forEach(v => targets.add(v)); paint(); });
      $('[data-pick-none]').addEventListener('click', () => { targets.clear(); paint(); });
      // 反选是全选/全不选都缺的那块：清单动辄几十项，手工逐个取消某一项最磨人。
      $('[data-pick-invert]').addEventListener('click', () => {
        all.forEach(v => { if (targets.has(v)) targets.delete(v); else targets.add(v); });
        paint();
      });

      // 清单与附带开关共用一套「点击 + Enter/Space」的处理器（委托到两个容器）。
      //
      // 为什么必须分两处而不合并成一个容器：附带开关在 `extras.length === 0` 时
      // **整个区块不渲染**，绑到不存在的节点上会在构造期抛 TypeError ——
      // 那正是「点立即执行毫无反应」的同款形态（见 escapeAttr 那条注释）。
      //
      // keydown 分支：Enter / Space 与 click 走同一条 toggle 路径，Space 额外
      // preventDefault 防页面滚动（AGENTS §2 自绘控件键盘路径）。
      const onPick = (e) => {
        const box = e.target.closest('.pick-box, .pick-extra-box');
        if (!box) return;
        if (e.type === 'keydown') {
          if (e.key !== 'Enter' && e.key !== ' ') return;
          e.preventDefault();
        }
        if (box.dataset.pickExtra !== undefined) {
          const id = box.dataset.pickExtra;
          setExtra(box, id, !pickedExtras.has(id));
        } else {
          const v = box.dataset.pick;
          setTarget(box, v, !targets.has(v));
        }
        syncCount();
      };
      $('.pick-list').addEventListener('click', onPick);
      $('.pick-list').addEventListener('keydown', onPick);
      const extrasBox = $('.pick-extras');
      if (extrasBox) {
        extrasBox.addEventListener('click', onPick);
        extrasBox.addEventListener('keydown', onPick);
      }

      $('[data-pick-ok]').addEventListener('click', () => {
        if (targets.size === 0) {
          window.app?.toast('warning', '一个目标都没勾选，请至少勾选一项后再执行');
          return;
        }
        finish({ targets: Array.from(targets), extras: Array.from(pickedExtras) });
        ctrl.close();
      });
      $('[data-pick-cancel]').addEventListener('click', () => ctrl.close());

      syncCount();
    });
  }

  // 阶段三：风险徽章统一 design-system（ds-badge sm：低=ok 中=warn 高=bad）
  function riskBadge(risk) {
    const type = risk === 'high' ? 'bad' : risk === 'medium' ? 'warn' : 'ok';
    const label = RISK_TEXT[risk] || risk;
    return window.ds
      ? window.ds.badgeHtml(type, label, { small: true })
      : `<span class="category-risk ${['low', 'medium', 'high'].includes(risk) ? risk : 'low'}">${label}</span>`;
  }

  function stepNote(s) {
    if (s.cmd) return s.cmd;
    if (s.service) return '停止服务 ' + s.service + (s.disable ? ' 并设为禁用' : '');
    if (s.reg) return '导入注册表项（多键值原样写入）';
    if (s.pwsh) {
      // 执行引擎如实报：数据层标 pwsh 的 56 个步骤里 45 个走主进程原生解释器
      // （execMode 由 optimizer:list 按 pssteps::compile 实算下发）。
      // 一律写「执行 PowerShell 内联脚本」是在谎报引擎，会让人以为应用依赖 PowerShell。
      if (s.execMode === 'inbox-ps') return '改系统设置（经系统自带的 Windows PowerShell，无需安装任何组件）';
      if (s.execMode === 'native') return '改系统设置（主进程原生执行）';
      if (s.execMode === 'unsupported') return '该步骤本机暂不支持（原生解释器与白名单都不认）';
      return '改系统设置（主进程执行）';
    }
    return '';
  }

  // v2.6.0（P2-7）：预期效果分级徽章（明显=accent / 一般=ok / 微小=neutral / 未验证=warn）
  const EFFECT_BADGE = { '明显': 'accent', '一般': 'ok', '微小': 'neutral', '未验证': 'warn' };
  function effectBadge(effect) {
    const type = EFFECT_BADGE[effect] || 'warn';
    return window.ds && window.ds.badgeHtml
      ? window.ds.badgeHtml(type, '效果·' + effect, { small: true })
      : `<span class="ds-badge ${type} sm">效果·${escapeHtml(effect || '未验证')}</span>`;
  }

  function renderSteps(steps) {
    if (!steps || !steps.length) return '<div class="opt-detail-steps-empty">无</div>';
    return '<ol class="opt-detail-steps">' + steps.map((s, i) => {
      const note = stepNote(s);
      return `<li><span class="opt-detail-step-label">${escapeHtml(s.label || ('第 ' + (i + 1) + ' 步'))}</span>` +
        (note ? `<code class="opt-detail-step-note">${escapeHtml(note)}</code>` : '') + '</li>';
    }).join('') + '</ol>';
  }

  // ==================== 列表渲染：胶囊卡片（一行 3 / 6 列） ====================
  // 优化中心分类过滤（'全部' 显示全部分组）
  let activeCategory = '全部';
  const OPT_CATEGORY_KEY = 'winclean-optcat-active';
  // 审查 2026-09-27 L11：「游戏安全诊断」无任何数据项映射（12 个最终展示组外），常驻
  // 空分类已删除；如日后新增该分组任务，在此补回即可
  const OPT_CATEGORIES = ['全部', '内存优化', '性能调优', '音频优化', '外设调优', '桌面体验', '任务调度', '系统服务', '隐私防护', '系统调校', '系统精简', '显卡优化', '浏览器优化'];

  function getSavedCategory() {
    try {
      const v = localStorage.getItem(OPT_CATEGORY_KEY);
      // 旧版本「系统清理」已并入「系统精简」，「网络优化」已移至系统维护-网络连接
      if (v === '系统清理') return '系统精简';
      if (v === '网络优化') return '全部';
      return OPT_CATEGORIES.indexOf(v) > -1 ? v : '全部';
    } catch (e) { return '全部'; }
  }

  function setCategory(cat) {
    activeCategory = OPT_CATEGORIES.indexOf(cat) > -1 ? cat : '全部';
    try { localStorage.setItem(OPT_CATEGORY_KEY, activeCategory); } catch (e) {}
    // 高亮页内「电脑优化中心」分类分段栏（原侧边栏分类子菜单）
    document.querySelectorAll('#optimizerCatNav .filter-tab').forEach(el => {
      const on = el.dataset.optcat === activeCategory;
      el.classList.toggle('active', on);
      el.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    renderGroups(OPTIONS);
  }

  // 渲染分类分段栏（按 OPT_CATEGORIES 生成，含侧边栏旧版未展示的分类）
  function renderCatNav() {
    const nav = document.getElementById('optimizerCatNav');
    if (!nav) return;
    nav.innerHTML = OPT_CATEGORIES.map(cat =>
      `<button class="filter-tab${cat === activeCategory ? ' active' : ''}" data-optcat="${escapeHtml(cat)}" role="tab" aria-selected="${cat === activeCategory}">${escapeHtml(cat)}</button>`
    ).join('');
    nav.querySelectorAll('[data-optcat]').forEach(btn => {
      btn.addEventListener('click', () => setCategory(btn.dataset.optcat));
    });
  }

  // ==================== 列表渲染：看板瀑布流（Masonry） ====================
  // 每个分类一列（白色圆角卡片），列内条目竖排：复选框 + 序号 + 名称（可换行不截断）+ 风险标签；
  // 列头 = 分类名 + 项数徽章；列底 = 「全选本类」；
  // 瀑布流：按升序顺序依次放入「最矮列」底部，列数按容器宽度自适应，1 看板占满整行，无横向滚动。
  let kanbanMasonry = null;
  function renderGroups(options) {
    const root = document.getElementById('optimizerGroups');
    if (!root) return;
    options = displayList(options);   // 虚拟卡顶掉被聚合的真实项（三态收在一张卡里）
    const byGroup = {};
    options.forEach(o => {
      const g = displayGroup(o);
      if (activeCategory !== '全部' && g !== activeCategory) return;
      (byGroup[g] = byGroup[g] || []).push(o);
    });
    const order = GROUP_ORDER.filter(g => byGroup[g]).concat(
      Object.keys(byGroup).filter(g => GROUP_ORDER.indexOf(g) === -1)
    );
    // 所有看板按项数从少到多升序排列（稳定排序，项数相同保持原相对顺序）
    order.sort((a, b) => byGroup[a].length - byGroup[b].length);
    const totalItems = order.reduce((s, g) => s + byGroup[g].length, 0);
    const summary = document.getElementById('optimizerSummary');
    if (summary) summary.textContent = `共 ${totalItems} 项优化 · ${order.length} 个分类`;
    root.innerHTML = `<div class="opt-kanban">` + order.map(group => {
      // 审查 M20：不再按分类注入离表 hex。`--c` / `--cf` 的 CSS 兜底本身就是
      // `var(--accent)` / `var(--accent-text)`（main.css:6335、:2589），少注入一层
      // 反而让主题与自定义 accent（pathbinding.applyAccent）能正常驱动看板配色。
      const items = byGroup[group];
      // 外设调优：列头提供「更多调优项」入口 → 打开外设优化窗口（Win32PrioritySeparation 等深度调优）
      const moreBtn = group === '外设调优'
        ? `<button type="button" class="opt-col-more" data-more-group="外设调优" data-tip="打开外设优化：处理器调度 / 鼠标队列深度调优">更多调优项</button>`
        : '';
      return `
      <section class="opt-col">
        <div class="opt-col-head">
          <span class="opt-col-title">${escapeHtml(group)}</span>
          ${moreBtn}
          <span class="opt-col-count">${items.length}</span>
        </div>
        <div class="opt-col-body">
          ${items.map((o, i) => renderOptRow(o, i + 1)).join('')}
        </div>
        <div class="opt-col-foot">
          <button type="button" class="opt-col-selectall" data-selectall-group="${escapeHtml(group)}" data-tip="全选本分类全部优化项">全选本类</button>
        </div>
      </section>`;
    }).join('') + `</div>`;
    if (!order.length) {
      root.innerHTML = window.emptyState
        ? window.emptyState({ icon: 'box', title: '该分类下暂无优化项', desc: '尝试切换左侧其它分类，或返回「全部」查看所有优化项目' })
        : '<div class="empty-state"><p>该分类暂无优化项目。</p></div>';
    }
    // ancel 对比审查 P1（2026-09-14）的「网络栈优化已移至系统维护」指引横幅已按用户要求移除
    // （2026-09-27）：网络栈优化迁移已跨多个版本，新用户无从知晓旧位置，横幅失去指引价值。
    // 瀑布流布局：重新渲染后立即放置；窗口 resize 由 attach 内部防抖 + FLIP 动画重排
    // 注意：布局容器是每次重渲染重建的 .opt-kanban，须用 getter 动态获取
    if (!kanbanMasonry && window.kanbanMasonry) {
      kanbanMasonry = window.kanbanMasonry.attach(
        () => root.querySelector('.opt-kanban'), '.opt-col', { gap: 14, minCard: 246 }
      );
    }
    if (kanbanMasonry) kanbanMasonry.relayout(false);
    updateSelectedButtonState();
  }

  // 看板条目行：复选框（固定）+ 序号（浅灰固定宽）+ 名称（自动换行，不省略）+ 风险标签（胶囊）
  // 已优化（optimizedIds 命中）的项整行灰态 + 「已优化」标签 + 复选框禁用，点击行弹出还原确认
  //
  // 2026-10-03 用户裁定：删除每行末尾的收藏星标（E10）。理由是它既无消费场景
  // （没有「只看收藏」筛选、没有收藏排序），又把每行最右侧的横向空间吃掉一格，
  // 长标题被挤成竖排单字。**不是隐藏，是整条链路下线**：渲染、事件、状态集合、
  // 后端命令、CHANNEL_MAP、门禁登记一并摘掉，避免留下永不被调用的死通道。
  function renderOptRow(o, index) {
    const id = escapeHtml(o.id);
    const isOpt = optimizedIds.has(o.id);
    // 2026-10-06（任务二）：**可否恢复只在详情弹窗判定**（弹窗消费 restorable / restoreAvailable），
    // 主列表只做灰显 + 「已优化」标签。行内的「立即恢复 / 无法还原」按钮已整条下线 ——
    // 一处判定、一处入口，避免两个地方对「能不能还原」各说各话（B4 的判据在弹窗里继续生效）。
    return `
      <div class="opt-row${isOpt ? ' optimized' : ''}" data-id="${id}" data-tip="${isOpt ? '该项优化已生效，点击查看详情与还原入口' : '点击查看「' + escapeHtml(o.title) + '」详情'}">
        <div class="checkbox${selectedIds.has(o.id) ? ' checked' : ''}${isOpt ? ' disabled' : ''}" data-check="${id}" data-tip="${isOpt ? '已优化的项不可勾选，点击行查看详情' : '勾选/取消选择该优化项'}"></div>
        <span class="opt-row-index">${index}</span>
        <span class="opt-row-name">${escapeHtml(o.title)}</span>
        ${riskBadge(o.risk)}${isOpt ? '<span class="opt-row-opttag">已优化</span>' : ''}
      </div>`;
  }

  // ==================== 安全托底：已优化检测与还原 ====================
  // 启动时异步批量检测含注册表操作的项是否已生效（不阻塞首屏），命中项灰态展示；
  // 点击灰态行弹「是否还原此项优化？」确认，「是」执行 restore 后恢复正常态。
  //
  // 审查 v3（2026-09-28 用户拍板）：灰态改为**三重来源取并集**——
  //   appliedLocal   = 本机执行成功后落盘的本地数据（localStorage，跨会话保留）
  //   appliedDetected= 主进程首启扫描的持久化记账（stateOverview.detected）
  //   appliedChecked = 本轮实时检测（checkOptimized / svcMemCurrent）
  // **命中任一即灰态**。旧实现把实时检测当权威源，检测为 false 时会把另外两个来源的记录
  // 一并 delete —— 于是「明明刚优化过，但因检测漏判（组策略覆盖/读取失败/项已变形）就变回
  // 未优化态」，用户可再次勾选执行，**重复优化造成损失**。灰态是防重复执行的唯一护栏，
  // 判据只能是「宁可多灰，不可漏灰」：误灰的代价是多点一次还原，漏灰的代价是不可逆的系统改动。
  // 只有**显式还原成功**才从三个来源同时清除。
  const optimizedIds = new Set();     // 渲染用的合并视图，禁止直接 add/delete，走 syncOptimized()
  const appliedLocal = new Set();     // 来源①：本机执行落盘
  const appliedDetected = new Set();  // 来源②：主进程持久化记账
  const appliedChecked = new Set();   // 来源③：实时检测

  const OPT_APPLIED_KEY = 'winclean-opt-applied-ids';

  function loadAppliedLocal() {
    try {
      const raw = JSON.parse(localStorage.getItem(OPT_APPLIED_KEY) || '[]');
      if (!Array.isArray(raw)) return;
      // 只认当前还存在的项：退役/改名项顺带清出，避免集合无限增长
      const known = new Set(OPTIONS.map(o => o.id));
      for (const id of raw) if (typeof id === 'string' && known.has(id)) appliedLocal.add(id);
    } catch (e) { /* 损坏即从空集合开始：漏灰有还原兜底，误灰会挡住合法操作 */ }
  }

  function saveAppliedLocal() {
    try {
      localStorage.setItem(OPT_APPLIED_KEY, JSON.stringify([...appliedLocal]));
    } catch (e) {
      window.app?.log?.('warn', '已优化记录落盘失败（本次会话有效，重启后需重新检测）');
    }
  }

  /** 合并三源 → optimizedIds，并刷新行样式 */
  function syncOptimized() {
    optimizedIds.clear();
    for (const s of [appliedLocal, appliedDetected, appliedChecked]) for (const id of s) optimizedIds.add(id);
    applyOptimizedStyles();
  }

  /** 执行成功落地：写本地数据并置灰（双保险的第一层） */
  function markAppliedLocal(id) {
    if (!id) return false;
    appliedLocal.add(id);
    saveAppliedLocal();
    syncOptimized();
    return true;
  }

  /** 显式还原成功：三个来源同时清除（唯一允许摘灰态的路径） */
  function clearAllApplied(id) {
    if (!id) return;
    appliedLocal.delete(id);
    appliedDetected.delete(id);
    appliedChecked.delete(id);
    saveAppliedLocal();
    syncOptimized();
  }

  function applyOptimizedStyles() {
    document.querySelectorAll('#optimizerGroups .opt-row').forEach(row => {
      const id = row.dataset.id;
      if (!id) return;
      const isOpt = optimizedIds.has(id);
      row.classList.toggle('optimized', isOpt);
      const check = row.querySelector('.checkbox');
      if (check) check.classList.toggle('disabled', isOpt);
      let tag = row.querySelector('.opt-row-opttag');
      if (isOpt && !tag) {
        tag = document.createElement('span');
        tag.className = 'opt-row-opttag';
        tag.textContent = '已优化';
        row.appendChild(tag);
      } else if (!isOpt && tag) {
        tag.remove();
      }
    });
  }

  // 已优化项标记：执行成功后立即置灰并**落本地数据**（用于用户刚操作完的即时反馈，
  // 且重启后仍在）。判断规则不变（dynamic / 含 reg·service.disable / 含 pwsh·cmd 步骤 → 标记）。
  function markOptimizedIfApplicable(opt) {
    if (!opt || !opt.id) return false;
    if (opt.dynamic) { markAppliedLocal(opt.id); return true; }
    const steps = Array.isArray(opt.steps) ? opt.steps : [];
    if (steps.length === 0) return false;
    markAppliedLocal(opt.id);
    return true;
  }

  // SVCHost 拆分阈值当前已应用的档位（'default' / 数字 gb / null=未优化）。
  // 来源：① 启动时读注册表映射 ② 本次会话执行成功后记录。
  let svcAppliedGb = null;

  function startOptimizedCheck() {
    if (!window.api?.optimizer?.checkOptimized) return; // 预览模式不检测
    // 检测范围：含 reg 块或服务禁用步骤的项（启动初始阶段静默扫描宿主机是否已完成该项优化）。
    // dynamic 项（svc_mem_gb）不参与启动时批量检测 —— 它是按当前内存档位动态判断的，
    // 由用户点击详情弹窗时根据实际注册表值单独判定。
    const checkIds = OPTIONS
      .filter(o => !o.dynamic && (o.steps || []).some(s => s && (typeof s.reg === 'string' || (s.service && s.disable))))
      .map(o => o.id);
    // dynamic 项单独检测：读当前注册表阈值映射档位，命中则该行灰态（已优化）
    if (window.api?.optimizer?.svcMemCurrent) {
      window.api.optimizer.svcMemCurrent().then(r => {
        if (r && r.success && r.gb != null) {
          svcAppliedGb = r.gb;
          appliedChecked.add('svc_mem_gb');
          syncOptimized();
        }
      }).catch((e) => {
        window.app?.log?.('warn', `SVCHost 档位检测失败（保留本地与记账灰态）: ${e && e.message ? e.message : e}`);
      });
    }
    if (!checkIds.length) return;
    window.api.optimizer.checkOptimized(checkIds).then(resp => {
      if (!resp || !resp.success || !resp.results) return;
      // 审查 v3：实时检测只维护自己那一源 —— 命中加、未命中撤，
      // **不再动 appliedLocal / appliedDetected**（旧实现 delete 掉了它们 → 漏灰 → 可重复优化）。
      for (const id of checkIds) {
        if (resp.results[id] === true) appliedChecked.add(id);
        else appliedChecked.delete(id);
      }
      syncOptimized();
    }).catch((e) => {
      // 审查 v3-L6：检测失败必须留痕。此时另外两源仍在，灰态不会因一次失败而消失。
      window.app?.log?.('warn', `优化状态检测失败（以本地与记账灰态为准）: ${e && e.message ? e.message : e}`);
    });
  }

  // 还原入口统一走这里：优先按执行前记录的注册表值恢复；
  // 无备份记录时回退到优化项预置的还原脚本。
  // v2.6.0（P0-1）：提升到模块级，供详情弹窗与「未完成还原」横幅一键还原共用。
  async function restoreOption(opt) {
    // v5 O-3：两条还原路径是**互补**，不是互斥。旧写法 reg 备份一成功就 return，于是预置
    // 还原步里非 reg 的那部分（服务启动类型 / 计划任务 / 文件）永不执行，而账已被
    // clearAllApplied 销掉、UI 弹「已恢复」—— tf_svc_extra5 实测就是只删了 WDI 值、
    // 4 个服务照旧 Disabled。
    // 顺序：先跑预置还原（数据层写的是"猜的出厂值"），再用值级备份回写 —— 真原值必须
    // 最后落，否则会被预置里的猜测覆盖。
    const hasPresetNonRegStep = Array.isArray(opt.restore) && opt.restore.some(s => !s || !s.reg);
    let ok = true;

    if (hasPresetNonRegStep) {
      ok = await runOptionActive({ restore: true }, opt);
      if (!ok) return false;
    }

    if (window.api?.optimizer?.restoreReg) {
      let r = null;
      try { r = await window.api.optimizer.restoreReg(opt.id); } catch (e) { /* 走回退 */ }
      if (r && r.success) {
        ok = true;
      } else if (hasPresetNonRegStep) {
        // 预置那半确实成了；但要说清"真原值没能回写"，否则用户以为恢复的是改前的状态。
        // 预置还原自己会销账，所以这里备份缺失（missing）是预期路径，不另判失败。
        if (r && !r.missing) {
          window.app?.log('warn', `预置还原已执行，但按备份回写失败（恢复的是数据层出厂值，非改前值）: ${opt.title || opt.id}: ${r.message || ''}`);
        }
        ok = true;
      } else {
        ok = false;
      }
    }

    // 既没有备份可回写、该项也没有非 reg 预置步 → 原回退路径：整项按预置脚本跑一次
    if (!ok && !hasPresetNonRegStep) {
      ok = await runOptionActive({ restore: true }, opt);
    }
    if (ok) {
      clearAllApplied(opt.id);
      renderGroups(OPTIONS);
      window.app?.toast('success', '已恢复：' + (opt.title || opt.id));
    }
    return ok;
  }

  // ==================== 未完成还原提醒（v2.6.0 P0-1 崩溃自愈） ====================
  // 启动时主进程对记账条目核对真实状态：pending（执行中断遗留）或「已应用但逐键检测
  // 不符」的项判定为 stale。顶部横幅展示 N 项，一键还原逐项按原值恢复（还原失败
  // 的记录保留，下次启动继续提示——还原失败不清账）。
  async function loadStateOverview() {
    if (!window.api?.optimizer?.stateOverview) return;
    try {
      const resp = await window.api.optimizer.stateOverview();
      if (!resp || !resp.success) return;
      // v2.7.0：主进程首启扫描的持久化结果先灰化（页面未到、扫描未跑完时也有即时反馈）。
      // 审查 v3：这是第二来源，与本机执行落盘（appliedLocal）取并集，不再被实时检测清掉。
      const detected = resp.detected || {};
      let prefill = 0;
      for (const [id, d] of Object.entries(detected)) {
        const opt = OPTIONS.find(o => o.id === id);
        if (!opt || opt.dynamic) continue;
        if (d && d.optimized === true && !appliedDetected.has(id)) { appliedDetected.add(id); prefill++; }
      }
      if (prefill || appliedLocal.size) syncOptimized();
      // v2-M14：`migration.restored / failed` 是空桩产物（启动从不自动还原，那两个数组
      // 永远是空的），据此弹的「已自动还原 N 项」是从未发生过的承诺，已删。
      // 现在字段给的是「本机仍留有注册表备份的退役项」，还原由用户点，走同一条已确认通道。
      const mig = resp.migration;
      if (mig && Array.isArray(mig.pending) && mig.pending.length) showRetiredBanner(mig.pending);
      const staleIds = (Array.isArray(resp.staleIds) ? resp.staleIds : []).filter(id => OPTIONS.some(o => o.id === id));
      if (staleIds.length) {
        // 根治（2026-10-03）：条目带失败子步原因——横幅文本与悬浮提示都从这里出
        const staleItems = staleIds.map(id => {
          const it = (resp.items || []).find(x => x && x.id === id) || null;
          return {
            id,
            reasons: (it && Array.isArray(it.partialReasons)) ? it.partialReasons.filter(Boolean) : []
          };
        });
        showStaleBanner(staleItems);
      }
    } catch (e) { /* 状态总览失败不影响正常使用 */ }
  }

  // 审查 2026-09-27 M8：重启后恢复上次因提权中断的批量——读回预勾选并提示续跑。
  // 键只在「同意提权且有批量上下文」时写入，恢复后立即清除，不产生循环提示。
  function restorePendingBatch() {
    let pending = null;
    try { pending = JSON.parse(localStorage.getItem(OPT_PENDING_BATCH_KEY) || 'null'); } catch (e) { /* 损坏即放弃 */ }
    if (!Array.isArray(pending) || !pending.length) return;
    try { localStorage.removeItem(OPT_PENDING_BATCH_KEY); } catch (e) { /* 同上 */ }
    // 提权前落盘的是**展开后的真实 id**；回到界面后被聚合项只以卡片形态存在，
    // 所以按 runId 反查回卡片 id —— 否则「已恢复勾选」恢复的是界面上根本没有的一行。
    const valid = pending
      .filter(id => OPTIONS.some(o => o.id === id))
      .map(id => { const g = virtualOfByRunId(id); return g ? g.id : id; });
    if (!valid.length) return;
    valid.forEach(id => selectedIds.add(id));
    renderGroups(OPTIONS);
    updateSelectedButtonState();
    window.app?.toast('info', `检测到上次因提权重启中断的优化批次（${valid.length} 项），已恢复勾选，可点「执行所选优化」继续`, 6000);
  }

  function showStaleBanner(items) {
    const banner = document.getElementById('optimizerStaleBanner');
    const text = document.getElementById('optimizerStaleText');
    if (!banner || !text) return;
    const ids = items.map(x => x.id);
    // 根治（2026-10-03）：partial 项带失败步数，悬浮提示给头部原因——
    // 此前「状态不明」无从判断该还原还是该重跑（明细只在日志里）。
    const names = items.slice(0, 3).map(x => {
      const t = getOptionTitle(x.id);
      return x.reasons.length ? `${t}（${x.reasons.length} 步失败）` : t;
    }).join('、') + (items.length > 3 ? ` 等 ${items.length} 项` : '');
    text.textContent = `检测到 ${items.length} 项优化改动未完成还原（${names}）：可能因执行中断或被系统回写导致状态不明。可退回原值，或把优化值重新写到位。`;
    const detail = items.flatMap(x => x.reasons.map(r => `${getOptionTitle(x.id)}：${r}`));
    if (detail.length) {
      text.setAttribute('data-tip', detail.slice(0, 8).join('；') + (detail.length > 8 ? `；等 ${detail.length} 条，完整明细见日志页` : ''));
    } else {
      text.removeAttribute('data-tip');
    }
    banner.style.display = 'flex';
    const btn = document.getElementById('btnStaleRestore');
    if (btn) {
      btn.onclick = async () => {
        btn.disabled = true;
        btn.textContent = '还原中…';
        let okCount = 0;
        for (const id of ids) {
          const opt = OPTIONS.find(o => o.id === id);
          if (!opt) continue;
          try { if (await restoreOption(opt)) okCount++; } catch (e) { /* 单项失败继续 */ }
        }
        banner.style.display = 'none';
        renderGroups(OPTIONS);
        window.app?.toast(okCount === ids.length ? 'success' : 'warning',
          `一键还原完成：成功 ${okCount} 项，共 ${ids.length} 项`);
      };
    }
    // 「一键应用」= 把状态不明的项重新写成优化目标值。刻意**不另起一条 apply 链**：
    // 直接把这批 id 装进选择集再走 runSelected，这样高危红色二次确认、还原点检查、
    // 提权中断续跑（batchRemainingIds）、批次生效粒度提示一条都不会绕过去。
    const applyBtn = document.getElementById('btnStaleApply');
    if (applyBtn) {
      const applicable = ids.filter((id) => OPTIONS.some((o) => o.id === id));
      applyBtn.disabled = applicable.length === 0;
      if (applicable.length === 0) {
        applyBtn.setAttribute('data-tip', '这些项已不在优化目录里，只能按原值还原');
      }
      applyBtn.onclick = async () => {
        // 保住用户此前的手勾：本入口只是"临时借用选择集"，不该把人家的勾选清掉
        const keep = new Set(selectedIds);
        selectedIds.clear();
        applicable.forEach((id) => selectedIds.add(id));
        await runSelected();
        if (keep.size) {
          selectedIds.clear();
          keep.forEach((id) => selectedIds.add(id));
          renderGroups(OPTIONS);
        }
      };
    }
    // 根治第三出口（2026-10-03 用户拍板）：「不再提醒」= per-id 记进主进程记账的
    // prefs.staleDismissed。该项重新执行（pending/applied/partial 落账）或还原销账时
    // 忽略自动失效——若又 partial 会重新提醒，旧忽略不会吞掉新状态。
    const dismissBtn = document.getElementById('btnStaleDismiss');
    if (dismissBtn) {
      dismissBtn.onclick = async () => {
        dismissBtn.disabled = true;
        try {
          const resp = await window.api.optimizer.staleDismiss(ids);
          if (resp && resp.success) {
            window.app?.toast('info', `已忽略这 ${ids.length} 项的启动提醒；重新执行或还原后忽略会自动失效`, 5000);
          } else {
            window.app?.toast('error', '忽略失败：' + ((resp && resp.message) || '未知原因'));
          }
        } catch (e) {
          window.app?.toast('error', '忽略失败：' + ((e && e.message) || e));
        }
        banner.style.display = 'none';
        dismissBtn.disabled = false;
      };
    }
  }

  // v2-M14：退役优化项的还原出口。这些 id 已不在优化目录里（所以详情弹窗、勾选项、
  // 常规还原横幅都找不到它们），但执行前记录的注册表原值还在备份文件里。
  // 刻意**不在启动时自动写回**：上游 Electron 轨那么做，而本应用的模型要求危险操作先确认。
  function showRetiredBanner(items) {
    const banner = document.getElementById('optimizerRetiredBanner');
    const text = document.getElementById('optimizerRetiredText');
    if (!banner || !text) return;
    const names = items.slice(0, 3).map(i => i.title || i.id).join('、')
      + (items.length > 3 ? ` 等 ${items.length} 项` : '');
    text.textContent = `${items.length} 项已退役优化在本机仍留有注册表备份（${names}）。`
      + 'Trim 不会在启动时静默写回系统设置，需要你确认后按备份的原值逐项还原。';
    banner.style.display = 'flex';
    const btn = document.getElementById('btnRetiredRestore');
    if (!btn) return;
    btn.onclick = async () => {
      const ok = await window.app?.confirmDanger?.(
        '按原值还原退役优化项',
        `将把 ${items.length} 项已退役优化在执行前记录的注册表原值写回系统（共 ${items.reduce((n, i) => n + (i.values || 0), 0)} 个值）。`,
        '确认还原',
        '取消',
        '这些项已从优化目录移除，除了这里没有别的还原入口；需要管理员权限。'
      );
      if (!ok) return;
      btn.disabled = true;
      btn.textContent = '还原中…';
      let done = 0;
      const fails = [];
      for (const it of items) {
        try {
          const r = await window.api.optimizer.restoreReg(it.id);
          if (r && r.success) done++;
          else fails.push(`${it.title || it.id}：${(r && r.message) || '未知错误'}`);
        } catch (e) {
          fails.push(`${it.title || it.id}：${e && e.message ? e.message : String(e)}`);
        }
      }
      if (done) {
        window.app?.toast('success', `已按原值还原 ${done} 项退役优化的改动`);
        window.app?.log('info', `退役优化项按备份还原成功 ${done} 项`);
      }
      if (fails.length) {
        // 失败不清账：备份还在，下次进页继续提示，用户提权后可再点一次
        window.app?.log('warn', `退役优化项还原失败 ${fails.length} 项：${fails.slice(0, 3).join('；')}`);
        window.app?.toast('warning', `${fails.length} 项还原失败（多为缺管理员权限），备份记录已保留`);
      }
      if (done && !fails.length) banner.style.display = 'none';
      btn.disabled = false;
      btn.textContent = '按原值还原';
    };
  }

  // ==================== 详情弹窗（v3.2.0 弹窗统一批次：迁移到 modal.js 工厂） ====================
  // 旧 opt-modal-* 自建骨架已删除；现在走 window.modal.create() 统一三段式
  // （usage-backdrop > usage-modal，含唯一 id / 焦点陷阱 / Esc 与遮罩关闭 / IPC 日志）。
  // 图1 专属视觉保留：齿轮图标 accent 着色、优缺点绿红双列、footer 左侧内存档位提示位。
  let optModal = null;     // 当前弹窗 ctrl（modal.create 返回值）
  let activeOption = null;

  function openModal(o, notice) {
    // E10：打开详情即记一次「最近使用」。
    // 失败**不打断**（不是用户主动操作，见 optimizer_touch_recent 的注释），
    // 只吞掉异常并在日志里留痕 —— 浮动 Promise 会变成 v2-M22 那一类静默失败。
    if (window.api?.optimizer?.touchRecent) {
      Promise.resolve(window.api.optimizer.touchRecent(o.id)).catch((e) => {
        window.app?.log('warn', '记录最近使用失败: ' + (e && e.message ? e.message : e));
      });
    }
    // 虚拟合集卡没有自己的 steps/restore，详情窗对它没有意义 —— 点开即弹「先选哪一态」。
    // openVirtualChoice 是 async：外层吞掉异常，否则点卡片就成了浮动 Promise（v2-M22 同族）。
    if (virtualOf(o.id)) {
      Promise.resolve(openVirtualChoice(o)).catch((e) => {
        window.app?.toast('error', 'Windows 更新调整异常：' + ((e && e.message) || e));
      });
      return;
    }
    // 重复打开（如执行后刷新按钮态）先关旧实例，保证唯一 id 与事件不叠加
    if (optModal) { optModal.close(); optModal = null; }
    activeOption = o;
    // 审查 M20：原来是 `background:${hex}18;color:${hex}` —— 拼在离表 hex 后面当 alpha 用，
    // 既不过 token 也无法随主题走。改用 --accent-soft 底 + --accent 前景。
    const iconStyle = 'style="background:var(--accent-soft);color:var(--accent)"';
    const stepCount = (o.steps || []).length;
    const metaHtml =
      riskBadge(o.risk) + effectBadge(o.effect) + `<span class="opt-detail-count">${stepCount} 步操作</span>`;
    // v2.6.0（P2-7）：预期效果说明——诚实口径：经验分级，非本机实测数据
    const EFFECT_HINT = {
      '明显': '收益通常可直观感知或量化较大（如后台占用明显减少、空间大幅释放）。',
      '一般': '机制明确，特定场景下有可测收益（如隐私面收敛、响应更干脆）。',
      '微小': '收益存在但多数场景难以感知，属于锦上添花。',
      '未验证': '缺乏可靠依据或收益因机型/负载而异，无法给出负责任的结论。'
    };
    const effectHint = `预期效果（${o.effect || '未验证'}）：${EFFECT_HINT[o.effect] || EFFECT_HINT['未验证']}——此为经验分级，非本机实测数据。`;
    const bodyHtml = `
      <div class="opt-detail-notice" style="display:none"></div>
      <p class="opt-detail-desc"></p>
      <p class="opt-detail-effect"></p>
      <div class="opt-detail-grid">
        <div class="opt-detail-col pros">
          <div class="opt-detail-col-label">优点</div>
          <p class="opt-detail-col-text opt-col-pros"></p>
        </div>
        <div class="opt-detail-col cons">
          <div class="opt-detail-col-label">缺点</div>
          <p class="opt-detail-col-text opt-col-cons"></p>
        </div>
      </div>
      <div class="opt-detail-section">
        <div class="opt-detail-section-title">详细操作</div>
        <div class="opt-detail-steps-wrap"></div>
      </div>
      <div class="opt-detail-section opt-pick-section" style="display:none">
        <div class="opt-detail-section-title opt-pick-title">逐项选择</div>
        <p class="opt-pick-hint"></p>
        <button class="btn btn-secondary opt-pick-open" type="button">逐项选择要执行的目标…</button>
      </div>`;
    const footerHtml = `
      <div class="opt-detail-mem" style="display:none"></div>
      <span class="model-picker-spacer"></span>
      <button class="btn btn-opt-ai opt-btn-ai">AI 生成优缺点</button>
      <button class="btn btn-secondary opt-btn-repair" style="display:none" data-tip="把服务启动类型改回自动，并恢复被停止的服务">修复服务启动类型</button>
      <button class="btn btn-secondary opt-btn-restore">还原</button>
      <button class="btn btn-accent opt-btn-run">立即执行</button>`;

    optModal = window.modal.create({
      id: 'optDetailModal-' + o.id,
      title: o.title || o.id,
      iconSvg: `<span class="opt-detail-icon" ${iconStyle}><svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor">${GEAR_ICON}</svg></span>`,
      metaHtml,
      bodyHtml,
      footerHtml,
      bodyClass: 'opt-detail-body'
    });
    // 审查 M20：这里原先把「分类强调色」覆盖进弹窗局部的 --accent/--accent-text，
    // 等于让 13 个离表 hex 劫持一次主题变量（自定义 accent 在这层会被静默换掉）。
    // 删掉覆盖后，弹窗内的强调色回到主题真源。
    const $ = (sel) => optModal.modal.querySelector(sel);
    $('.opt-detail-desc').textContent = o.desc || '（无描述）';
    $('.opt-detail-effect').textContent = effectHint;
    $('.opt-col-pros').textContent = o.pros || '暂缺，可点击下方「AI 生成优缺点」重新生成。';
    $('.opt-col-cons').textContent = o.cons || '暂缺，可点击下方「AI 生成优缺点」重新生成。';
    $('.opt-detail-steps-wrap').innerHTML = renderSteps(o.steps);

    // 逐项选择（2026-10-03 用户裁定）：这三项此前只有「一键全选 / 一键全还原」，
    // 用户看到的是「禁用 70 个服务」这种不可拆的黑箱 —— 里面有 CryptSvc（证书与
    // BitLocker 全靠它）也有 RetailDemo（一眼可弃），让人「一把梭」等于逼他在
    // 「全选」和「放弃」之间二选一。默认**全选**（不改变既有行为），可逐项取消。
    //
    // 形态变更（同日第二轮）：勾选区已搬成**独立弹窗**（点「立即执行」后弹出）。
    // 这里退化为一个入口条 + 勾选状态的持有者。原因见 confirmSubitemPick 的注释：
    // 内嵌版藏在详情弹窗下方要滚动才看到，用户反馈「弹窗没有出现」，
    // 而且它逼着详情弹窗一直开着，好与高危确认框叠在一起互相抢焦点。
    const pickState = { targets: new Set(), extras: new Set(), all: [] };
    if (hasSubitemPick(o)) {
      // ⚠️ 这一段只负责「入口条」的装饰与预览，**主按钮的绑定在它后面**。
      // 以前这里是裸代码：`$('.opt-pick-section').style.display = ''` 一旦因为
      // 模板与选择器漂移拿到 null，异常会一路冒到 openModal 末尾，
      // 于是「立即执行」按钮**连监听器都没绑上** —— 点了毫无反应、连日志都只有
      // 一行未处理拒绝（与 escapeAttr 同款形态，同一份「静默失效」家族）。
      // 装饰性代码不许有能力杀掉主流程，所以整段兜 try/catch 并写日志。
      try {
        $('.opt-pick-section').style.display = '';
        $('.opt-pick-title').textContent = o.subitems.label || '逐项选择';
        // 「还有 N 个没有单独说明」必须如实说：清单里没登记解释的目标不列出来，
        // 不说的话用户会以为「全选」就是这 M 项。
        const un = Number(o.subitems.unexplained) || 0;
        o.subitems.items.forEach(it => { pickState.targets.add(it.value); pickState.all.push(it.value); });
        const openBtn = $('.opt-pick-open');
        const entryTotal = Number(o.subitems.total) || pickState.all.length;
        const paintEntry = () => {
          openBtn.textContent = `逐项选择要执行的目标…（已选 ${pickState.targets.size} / ${entryTotal} 项）`;
        };
        $('.opt-pick-hint').textContent = (o.subitems.hint || '')
          + (un > 0 ? `（另有 ${un} 个目标未单独列出说明，全选时仍会执行。）` : '')
          + '点击下方按钮逐项确认。';
        // 入口按钮：就地预览勾选（预览不改执行语义，只让用户先看清范围）。
        // 与「立即执行」里那一次是同一个弹窗、同一份状态，不会出现两处结论。
        openBtn.addEventListener('click', async () => {
          const r = await confirmSubitemPick(o, pickState).catch(() => null);
          if (!r) return;
          pickState.targets = new Set(r.targets);
          pickState.extras = new Set(r.extras);
          paintEntry();
        });
        paintEntry();
      } catch (e) {
        // 入口条画不出来**不许**连带「立即执行」失效：清空 targets 让它退回
        // 「未指定子集 = 全选」的既有语义（与 v0.5.6 上线前的行为一致），
        // 逐项勾选仍会在点「立即执行」时以独立弹窗形态出现（它不依赖本区块）。
        pickState.targets.clear();
        window.app?.log?.('warn', `逐项选择入口条渲染失败（该项将按全选执行）: ${(e && e.message) || e}`);
      }
    }

    // 安全兜底：已优化项「立即执行」→「立即恢复」；无法推理还原操作时按钮置灰。
    // dynamic 项（svc_mem_gb）例外：不走恢复流，由下方档位联动决定按钮态
    // （当前档位已应用 → 置灰；选择其他档位 → 可立即执行）。
    const isOpt = optimizedIds.has(o.id);
    const runBtn = $('.opt-btn-run');
    if (isOpt && !o.dynamic) {
      const canRestore = !!o.restoreAvailable && Array.isArray(o.restore) && o.restore.length > 0;
      runBtn.textContent = '立即恢复';
      runBtn.disabled = !canRestore;
      runBtn.dataset.mode = 'restore';
      if (!notice) {
        // 任务二（2026-10-06）：主列表不再有行内还原按钮，「可否恢复」在此**唯一判定**。
        // `restorable` 由后端逐行注入（`catalog.rs::is_restorable`，值 = 本机值级备份的键数）；
        // >0 时把「按本机备份逐值还原」讲出来（restoreOption 会经 restoreReg 把真原值回写），
        // 否则这个字段在前端就是零消费方的死字段。
        const backupHint = (typeof o.restorable === 'number' && o.restorable > 0)
          ? `本机存有值级备份：按本机备份逐值还原（${o.restorable} 个值）。`
          : '';
        notice = canRestore
          ? `您已完成优化。点击「立即恢复」将删除对应的注册表修改，恢复系统默认状态。${backupHint}`
          : '您已完成优化，该项暂不提供恢复功能';
      }
    } else if (!o.dynamic) {
      runBtn.textContent = '立即执行';
      runBtn.disabled = false;
      runBtn.dataset.mode = 'run';
    }
    // 安全兜底提示条：在按钮态确定后渲染（notice 由上方分支生成）
    // R0-c：若该项属 startType 修复范围，notice 补一条 v0.5.0 存量受害者提示。
    // 不覆盖已有 notice（灰态项的还原提示更该优先），用追加。
    const repairBtn = $('.opt-btn-repair');
    if (needsStartTypeRepair(o)) {
      repairBtn.style.display = '';
      const svc = (o.steps || []).find(s => s && s.service);
      const svcName = svc ? svc.service : '';
      notice = (notice ? notice + '　' : '') +
        '若你的机器上该服务当前是「已停止」，这是 v0.5.0 的一处缺陷所致（当时只停了服务、没改启动类型）。点「修复服务启动类型」可把' +
        (svcName ? '「' + svcName + '」' : '该服务') + '启动类型改回自动并重新启动它。';
    }
    const noticeEl = $('.opt-detail-notice');
    if (notice) {
      noticeEl.textContent = notice;
      noticeEl.style.display = 'block';
    }

    // 动态 / 还原：footer 左侧档位提示位（图1 专属视觉，保留）
    // 审查 v2-M10：控件与参数一律按 opt.id 从 DYNAMIC_CONTROLS 取，不再按 `dynamic` 一刀切。
    const memWrap = $('.opt-detail-mem');
    const restoreBtn = $('.opt-btn-restore');
    const dyn = DYNAMIC_CONTROLS[o.id];
    if (o.dynamic && !dyn) {
      // 数据层说是 dynamic、本表却没登记控件 —— 这正是 v2-M10 的失法形态（后端要参数、前端不发，
      // 表现为「该项永远执行失败」而不报错）。宁可锁死按钮并写明原因，也不放一条注定失败的请求。
      memWrap.style.display = 'none';
      runBtn.disabled = true;
      runBtn.dataset.mode = 'blocked';
      runBtn.textContent = '界面未登记参数控件';
    } else if (dyn) {
      memWrap.style.display = '';
      memWrap.innerHTML = '<select class="field-input optimizer-mem-select opt-dyn-select" data-tip="' + escapeHtml(dyn.tip) + '">' +
        dyn.options.map(m => `<option value="${escapeHtml(m.value)}">${escapeHtml(m.label)}</option>`).join('') + '</select>';
      const sel = memWrap.querySelector('.opt-dyn-select');
      // 根据下拉档位实时刷新优缺点与步骤显示
      function updateVariant() {
        const v = dyn.parse(sel.value);
        const info = dyn.prosCons ? dyn.prosCons(v) : null;
        if (info) {
          $('.opt-col-pros').textContent = info.pros;
          $('.opt-col-cons').textContent = info.cons;
        }
        // 步骤区：显示当前档位/天数对应的执行说明（label 与 note 都过转义，虽然值来自本表）
        $('.opt-detail-steps-wrap').innerHTML =
          `<ol class="opt-detail-steps"><li><span class="opt-detail-step-label">${escapeHtml(dyn.stepLabel(v))}</span>` +
          `<code class="opt-detail-step-note">${escapeHtml(dyn.stepNote(v))}</code></li></ol>`;
        $('.opt-detail-count').textContent = '1 步操作';
      }
      // 档位联动按钮态：当前已应用的档位 → 置灰（无后续操作）；选择其他档位 → 启用「立即执行」。
      // 只有 svc_mem_gb 有「当前已应用档位」这个概念（读注册表反推），暂停更新天数没有，故按 id 收口。
      function syncRunBtnForGear() {
        if (o.id !== 'svc_mem_gb') return;
        runBtn.dataset.mode = 'run';
        const selGb = String(sel.value);
        if (svcAppliedGb != null && selGb === String(svcAppliedGb)) {
          runBtn.disabled = true;
          runBtn.textContent = svcAppliedGb === 'default'
            ? '当前已是默认档位'
            : `已应用 ${svcAppliedGb} GB 档位`;
        } else {
          runBtn.disabled = false;
          runBtn.textContent = '立即执行';
        }
      }
      sel.addEventListener('change', () => { updateVariant(); syncRunBtnForGear(); });
      // 初始档位：优先选中当前已应用的档位（未优化时回到本表 defaultValue，与后端默认对齐）
      sel.value = (o.id === 'svc_mem_gb' && svcAppliedGb != null) ? String(svcAppliedGb) : dyn.defaultValue;
      updateVariant();
      syncRunBtnForGear();
      // 兜底：弹窗打开后异步刷新一次注册表实际档位（防止启动检测尚未返回）
      if (o.id === 'svc_mem_gb' && window.api?.optimizer?.svcMemCurrent) {
        window.api.optimizer.svcMemCurrent().then(r => {
          if (!r || !r.success) return;
          if (activeOption !== o) return; // 弹窗已切走，丢弃
          svcAppliedGb = r.gb;
          if (r.gb != null) {
            appliedChecked.add(o.id);
            syncOptimized();
          }
          sel.value = (r.gb != null) ? String(r.gb) : sel.value;
          updateVariant();
          syncRunBtnForGear();
        }).catch(() => {});
      }
    } else {
      memWrap.style.display = 'none';
    }
    restoreBtn.style.display = o.restore ? '' : 'none';

    const aiBtn = $('.opt-btn-ai');
    aiBtn.disabled = false;
    aiBtn.textContent = 'AI 生成优缺点';

    // 弹窗按钮：立即执行（未优化）/ 立即恢复（已优化灰项）/ 还原 / AI
    // （v3.2.0：每次 open 重建 DOM，事件绑定随实例走；还原入口 restoreOption 为模块级共用）
    runBtn.addEventListener('click', async () => {
      if (!activeOption) return;
      const opt = activeOption;
      if (runBtn.dataset.mode === 'restore') {
        // 立即恢复：优先按备份还原
        closeOptModal();
        const ok = await restoreOption(opt);
        if (!ok) {
          // 还原未能执行：展示简介 + 提示
          openModal(opt, '还原未能执行。您已完成优化，该项暂不提供恢复功能');
        }
        return;
      }
      // ⚠️ 读取顺序：所有依赖详情弹窗 DOM 的取值必须在 closeOptModal 之前完成。
      // 与 dynamic 档位同一个坑：弹窗一关 optModal 置 null，后续 querySelector
      // 恒返回 undefined；而且更致命的是 —— 读不到就等于「没指定 = 全选」，
      // 用户只勾了 3 个却禁了 70 个，且回执照样报「完成」。
      //
      // 2026-10-03：这里新增了「先关详情弹窗、再弹确认」的顺序修正。
      // 原顺序是 confirmHazard 先弹、closeOptModal 后关 ⇒ 两个弹窗叠在 DOM 里，
      // 红色确认框被详情弹窗的遮罩压住（z 序与焦点都被抢），用户点「仍然执行」
      // 时框已经「一闪而过」。新顺序保证任何时刻只有一个弹窗。
      const dynCtl = DYNAMIC_CONTROLS[opt.id];
      let preCloseRaw = null;
      if (opt.dynamic && dynCtl) {
        const selEl = optModal?.modal?.querySelector('.opt-dyn-select');
        preCloseRaw = selEl ? selEl.value : dynCtl.defaultValue;
      }
      const prePick = hasSubitemPick(opt)
        ? {
            targets: new Set(pickState.targets),
            extras: new Set(pickState.extras),
            all: pickState.all.slice()
          }
        : null;
      // 详情弹窗立刻关闭：确认框/逐项选择框要成为唯一可见弹窗。
      // 用户若在后续确认里点「取消」，详情弹窗不会回来（下方 return 明确不再 openModal）
      // —— 这是刻意取舍：重开详情弹窗会再次触发「刚点的按钮被重建」的连锁。
      closeOptModal();

      // 逐项选择（2026-10-03 用户裁定）：点「立即执行」后弹**独立弹窗**逐项勾选，
      // 不再是详情弹窗内嵌的一个区块（内嵌版用户反馈「弹窗没出现」——
      // 它藏在详情下方，要滚动才看得到，被当成了不存在）。
      // 附带开关（extras）也一起在这里确认，默认仍全不选（默认改旧行为=静默越权）。
      const picked = prePick ? await confirmSubitemPick(opt, prePick) : null;
      if (prePick && picked === null) return; // 用户取消逐项选择，不执行

      const pickParams = picked
        ? { pickedTargets: picked.targets, pickedExtras: picked.extras }
        : {};

      const go = await confirmHazard(opt);
      if (!go) return;
      // tf_svc_bulk：单独弹窗询问是否连商店相关服务一并禁用（用户选择经 params 传递）
      const includeStore = opt.id === 'tf_svc_bulk' ? await confirmIncludeStoreServices() : false;
      // 执行前检查系统还原点（警示/风险确认；用户最终拒绝则不执行）。
      // （原「tf_restore_point 本身就是创建动作、直接放行」的特例判断已随条目摘除删除。）
      if (!(await ensureRestorePoint())) return;
      if (opt.dynamic && dynCtl) {
        const dynP = dynamicParams(opt.id, preCloseRaw);
        // 本会话立即记录已应用档位：重开弹窗时该档位按钮置灰（只有 mem 档有这个概念）
        if (opt.id === 'svc_mem_gb') svcAppliedGb = dynP.gb;
        // B11：与 runBatch 对齐 —— await + try/catch，避免浮动 Promise 变成
        // unhandled rejection（用户侧表现为「点击后毫无反应」）
        try {
          await runOptionActive(dynP, opt);
        } catch (e) {
          window.app?.toast('error', '优化执行失败: ' + (e.message || e));
        }
      } else {
        try {
          await runOptionActive(
            opt.id === 'tf_svc_bulk'
              ? Object.assign({ includeStore }, pickParams)
              : pickParams,
            opt
          );
        } catch (e) {
          window.app?.toast('error', '优化执行失败: ' + (e.message || e));
        }
      }
    });
    restoreBtn.addEventListener('click', async () => {
      const opt = activeOption;
      closeOptModal();
      await restoreOption(opt);
    });

    // R0-c 修复入口：把服务启动类型改回自动 + 重新启动服务。
    // 走已有的 restoreOption（预置 restore 步骤 = startType 'automatic'，R0-a 已让它真正
    // 生效且不再停服）。刻意不做「自动检测到就静默修」：静默改系统状态是本仓红线。
    repairBtn.addEventListener('click', async () => {
      const opt = activeOption;
      if (!opt || !needsStartTypeRepair(opt)) return;
      const svc = (opt.steps || []).find(s => s && s.service);
      const svcName = svc ? svc.service : '该服务';
      const go = await window.app.confirmDanger(
        '修复服务启动类型',
        '将把「' + svcName + '」的启动类型改回「自动」并重新启动它。' +
        '若你确实想让它保持手动，请点「取消」并直接关闭本窗口。',
        '修复', '取消',
        '只影响这一个服务的启动类型，不改其他系统设置。'
      );
      if (!go) return;
      repairBtn.disabled = true;
      repairBtn.textContent = '修复中…';
      closeOptModal();
      const ok = await restoreOption(opt);
      if (!ok) {
        window.app?.toast?.('error', '修复未完成：' + svcName + ' 启动类型未能改回自动，请稍后重试或用 services.msc 手动处理');
      } else {
        window.app?.toast?.('success', '已修复：' + svcName + ' 启动类型已改回自动');
      }
    });
    aiBtn.addEventListener('click', genAdviceActive);
  }

  function closeOptModal() {
    if (optModal) { optModal.close(); optModal = null; }
    activeOption = null;
  }

  // ==================== 执行 & AI ====================
  let OPTIONS = [];

  // ==================== 生效粒度（applyScope，BoosterX §B2）====================
  // 档位序与 Rust 侧 SCOPE_RANK 同表（commands/optimizer.rs），两侧一致性由
  // tools/check-optimizer-dynamic.mjs 对拍；display-driver / logoff 刻意不存在 ——
  // 本应用没有重启显卡驱动与登出的执行原语，给一个做不到的档位等于把猜测写进建议。
  const SCOPE_RANK = { none: 0, explorer: 1, reboot: 2 };

  function scopeAdviceText(rank, count) {
    if (rank >= SCOPE_RANK.reboot) {
      return `本批有 ${count} 项需要重启电脑才完全生效，重启前部分改动可能看不出来`;
    }
    if (rank >= SCOPE_RANK.explorer) {
      return `本批有 ${count} 项建议重启资源管理器后生效（右键菜单页可一键重启），未重启前界面可能不变`;
    }
    return '';
  }

  function getOptionTitle(id) {
    const o = OPTIONS.find(x => x.id === id);
    return o ? o.title : id;
  }

  // 批量执行的参数来源（v2-M10 → 2026-09-30 改口径）：dynamic 项与虚拟多态卡一律取自
  // promptUserChoices 弹出的选择窗。**不再退回分派表 defaultValue** —— 那等于「用户没表态，
  // 我们替他挑了暂停 7 天」，而更新策略猜错方向的代价不对称。
  // 返回 null = 这条压根没选定：调用方必须跳过并如实计入失败，不能发一条注定失败的请求。
  function batchParams(opt, paramsByRun) {
    if (paramsByRun && paramsByRun.has(opt.id)) return paramsByRun.get(opt.id);
    if (opt.dynamic) return null;
    return {};
  }

  // 批量前置闸：把勾到的「虚拟多态卡 / dynamic 项」一次性收进同一张选择窗。
  // 返回 Map<runId, params>；用户取消即 null（整批中止）。无需选择的批次直接返回空表。
  async function collectBatchChoices(entries) {
    const pending = entries.filter(needsUserChoice);
    if (!pending.length) return new Map();
    return await promptUserChoices(pending);
  }

  async function runOptionActive(params, optOverride) {
    const opt = optOverride || activeOption;
    if (!opt) return false;
    if (!window.api?.optimizer) {
      window.app?.toast('warning', '当前为预览模式，无法执行优化');
      return false;
    }
    // 用户要求：所有 PowerShell 注册表操作在执行前记录当前真实值，
    // 还原时直接按记录恢复。这里统一拦截（单项/批量执行都经过本函数）。
    if (!(params && params.restore) && window.api.optimizer.backupReg) {
      try {
        const bk = await window.api.optimizer.backupReg(opt.id);
        if (!bk || !bk.success) {
          window.app?.toast('error', `无法备份「${opt.title || opt.id}」，已停止执行`);
          return false;
        }
        if (bk.count > 0) window.app?.log('info', `已记录当前注册表值（${bk.count} 项）: ${opt.title || opt.id}`);
      } catch (e) {
        window.app?.toast('error', `备份「${opt.title || opt.id}」失败，已停止执行`);
        return false;
      }
    }
    createProgressToast(opt.title || '…');
    try {
      const t = progressToast;
      const titleEl = t && t.el ? t.el.querySelector('.toast-title') : null;
      const optName = opt.title || opt.id;
      if (t && t.el) { t.title = optName; const tune = t.el.querySelector('.toast-tune'); if (tune) tune.textContent = '正在执行「' + optName + '」…'; }
      setProgressToastProgress(1);
      // OPT-1（2026-09-15 v7）：高危项红色确认已在上游通过，这里携带服务端镜像回执；
      // restore 还原方向不属高危写入，不带标记。
      // v2-K3：判据必须与 confirmHazard 同一个函数，否则「前端弹了确认但后端不认」或
      // 「后端要回执而前端没给」都会出现——后者会让那 7 项 data-layer high 直接锁死。
      const runParams = Object.assign({}, params || {});
      if (!runParams.restore && needsHazardConfirm(opt)) runParams.confirmedHighRisk = true;
      const resp = await window.api.optimizer.run(opt.id, runParams);
      if (resp && resp.success) {
        finishProgressToast(true, resp.message);
        window.app?.log('info', `优化电脑完成: ${optName}`);
        // v2.6.0（P0-2）：执行后回读校验不符（主进程已逐键比对）——明确告知而非静默成功。
        // 2026-09-30：日志只留后端那一条（optimizer.rs 的执行后/还原后各一），这里不再重复记，
        // 同一次失败在日志页出现两行会把真实的一条挤下去；toast 是用户侧唯一回执，保留。
        if (resp.verify === 'partial') {
          window.app?.toast('warning', `「${optName}」已执行但读回校验不符，可能被组策略或安全软件覆盖`, 6000);
        }
        // 安全托底：执行成功后立即标记为已优化（灰态）+ 落本地数据
        if (params && params.restore) {
          clearAllApplied(opt.id);
        } else {
          markOptimizedIfApplicable(opt);
        }
        // 若弹窗还开着（还原时）则刷新按钮态；若已关闭则刷新列表灰态
        // （v3.2.0：activeOption 在弹窗关闭时置空，存在即代表弹窗开着）
        if (activeOption && activeOption.id === opt.id) {
          // 重新打开以刷新按钮态（已优化 ↔ 未优化）
          openModal(opt);
        } else {
          applyOptimizedStyles();
        }
        return true;
      }
      // 复核 N3（提权半闭环，2026-09-16）：服务端 OPT-1 门禁返回 needAdmin 时，
      // 此前只报「优化失败」死路；现在弹提权确认，管理员重启后重试即可
      if (resp && resp.needAdmin) {
        finishProgressToast(false, '需要管理员权限');
        // 审查 2026-09-27 M8：同意提权 → 应用即将重启，先把批量剩余写进 localStorage，
        // 重启进页时恢复预勾选（见 restorePendingBatch）；单项执行 batchRemainingIds
        // 为 null，不写键、行为不变
        const elevated = await window.app?.requestElevation?.('优化电脑部分选项需要管理员权限才能修改系统注册表与服务。');
        if (elevated) {
          if (batchRemainingIds && batchRemainingIds.length) {
            try { localStorage.setItem(OPT_PENDING_BATCH_KEY, JSON.stringify(batchRemainingIds)); } catch (e) { /* 存储不可用时降级为提示重试 */ }
          }
          window.app?.toast('info', '已获得管理员权限，请重新执行本优化项');
        }
        return false;
      }
      // 审查 2026-09-27 H1 兜底：Rust 侧还原方向已豁免回执闸门，正向链也总带标记；
      // 若仍收到 needConfirm（契约被破坏的信号），如实呈现而不是并进泛化的「优化失败」
      if (resp && resp.needConfirm) {
        finishProgressToast(false, resp.message || '缺少高危确认回执');
        window.app?.log('warn', `优化电脑被拒: ${optName}: 缺少高危确认回执`);
        return false;
      }
      // 审查 2026-09-27 M4：后端随回执下发逐步失败原因（failedSteps），toast 展示前
      // 3 条、完整清单进日志，不再只有一句「部分步骤可能失败」
      const failedSteps = (resp && Array.isArray(resp.failedSteps)) ? resp.failedSteps : [];
      const detail = failedSteps.length
        ? `${resp.message || '部分步骤失败'}（${failedSteps.slice(0, 3).join('；')}${failedSteps.length > 3 ? ' 等' : ''}）`
        : (resp && resp.message);
      finishProgressToast(false, detail);
      window.app?.log('warn', `优化电脑失败: ${optName}: ${detail || ''}${failedSteps.length ? ' | 全部: ' + failedSteps.join('；') : ''}`);
      return false;
    } catch (e) {
      finishProgressToast(false, e.message);
      window.app?.toast('error', '优化执行异常: ' + e.message);
      return false;
    }
  }

  // 执行任意优化前检查系统还原点（返回 true 放行 / false 中止）：
  // - 5 天内已有还原点 → 静默放行，不弹任何提示（还原点本就无需重复创建）
  // - 查询失败 → 放行并记日志（查询失败 ≠ 无还原点，不误报骚扰）
  // - 未创建（或超 5 天）→ 弹警示建议创建；用户拒绝创建时追加一次红色风险确认，
  //   再拒绝则中止本次执行，避免「点否后仍无条件放行」
  async function ensureRestorePoint() {
    if (!window.api?.optimizer?.checkRestore) return true; // 预览模式直接放行
    let resp;
    try {
      resp = await window.api.optimizer.checkRestore();
    } catch (e) {
      window.app?.log?.('warn', '还原点检查异常（已放行）: ' + (e && e.message || e));
      return true;
    }
    if (!resp || !resp.success) {
      // 2026-09-30：这一条不再记日志——后端 optimizer_check_restore 对每个失败出口都已写
      // warn（RPERROR / 脚本未跑成 / 无有效输出），前端再记一遍就是同事件双行。
      // 放行策略仍在这里：查询失败 ≠ 无还原点，不能据此弹「建议创建」骚扰用户。
      return true;
    }

    const FIVE_DAYS = 5 * 24 * 60 * 60 * 1000;
    if (resp.exists && resp.created) {
      const created = new Date(resp.created);
      if (!isNaN(created) && (Date.now() - created.getTime()) <= FIVE_DAYS) {
        return true; // 5 天内已有还原点：直接放行
      }
    }
    // 未创建或已超过 5 天：弹警示窗口建议创建
    const ok = await window.app.confirm(
      '系统还原点提醒',
      '检测到 5 天内没有可用的系统还原点。\n\n优化操作存在风险，建议先创建还原点——出现异常时可在「系统还原点管理」中一键回退。\n\n是否立即创建？',
      '立即创建',
      '暂不创建'
    );
    if (ok) {
      let cr;
      try { cr = await window.api.optimizer.createRestore(); } catch (e) { cr = null; }
      if (cr && cr.success) {
        window.app?.toast('success', '已创建系统还原点，可放心优化');
        return true;
      }
      window.app?.toast('warning', (cr && cr.message) || '还原点创建失败，建议先手动创建再优化');
    }
    // 未创建还原点（用户拒绝或创建失败）：红色风险确认，拒绝则中止
    const go = await window.app.confirmDanger(
      '未创建还原点继续执行？',
      '未创建还原点的情况下执行优化，出现问题将无法通过系统还原回退。',
      '仍要执行优化',
      '取消',
      '建议先创建还原点再执行优化。'
    );
    window.app?.log?.('info', go
      ? '用户在未创建还原点的情况下经风险确认后继续执行优化'
      : '用户拒绝在未创建还原点的情况下执行优化，已中止');
    return go;
  }

  // tf_svc_bulk 专用：执行前单独弹窗询问是否连商店相关服务一并禁用（用户需求 2026-09-14）。
  // 点「禁用」= 基础清单 + 商店 5 服务（ClipSVC/InstallService/PushToInstall/wuauserv/DoSvc）；
  // 点「不禁用」= 按现有方案执行（商店/同步保持默认）。返回 includeStore 布尔。
  async function confirmIncludeStoreServices() {
    try {
      return await window.app.confirmWarning(
        '禁用商店相关服务',
        '您是否要禁用商店相关服务，此功能会影响Windows应用商店的使用更新与下载',
        '禁用',
        '不禁用',
        '选择「禁用」将额外禁用 ClipSVC、InstallService、PushToInstall、wuauserv（Windows 更新）、DoSvc（传递优化下载）'
      );
    } catch (e) {
      window.app?.log?.('warn', '商店服务询问弹窗异常（按不禁用处理）: ' + (e && e.message || e));
      return false;
    }
  }

  async function genAdviceActive() {
    if (!activeOption) return;
    if (!window.api?.optimizer?.genAdvice) {
      window.app?.toast('warning', '当前为预览模式，无法调用 AI');
      return;
    }
    const btn = optModal?.modal?.querySelector('.opt-btn-ai');
    if (!btn) return;
    btn.disabled = true;
    const prev = btn.textContent;
    btn.textContent = '生成中…';
    try {
      const resp = await window.api.optimizer.genAdvice(activeOption.id);
      if (resp && resp.success && resp.data) {
        if (resp.data.pros) { optModal.modal.querySelector('.opt-col-pros').textContent = resp.data.pros; activeOption.pros = resp.data.pros; }
        if (resp.data.cons) { optModal.modal.querySelector('.opt-col-cons').textContent = resp.data.cons; activeOption.cons = resp.data.cons; }
        window.app?.toast('success', '已通过 ' + (resp.data.source || 'AI') + ' 生成优缺点');
      } else {
        window.app?.toast('error', (resp && resp.message) || 'AI 生成失败');
      }
    } catch (e) {
      window.app?.toast('error', 'AI 生成异常: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }

  // ==================== 部分选择执行 ====================
  let selectedIds = new Set(); // 已勾选的优化项 id（跨分组/分类保留）
  // 审查 2026-09-27 M8：批量执行中触发提权时，应用会以管理员身份重启、内存勾选集
  // 全部丢失。剩余批次在提权确认瞬间写入 localStorage，重启进页时恢复为预勾选并提示，
  // 用户点「执行所选优化」即可续跑；单项执行（无批量上下文）不写键、行为不变。
  const OPT_PENDING_BATCH_KEY = 'winclean-opt-pending-batch';
  let batchRemainingIds = null;

  function toggleSelect(id) {
    if (optimizedIds.has(id)) return; // 已优化项不可勾选（点击行走还原确认流程）
    if (selectedIds.has(id)) selectedIds.delete(id);
    else selectedIds.add(id);
    const row = document.querySelector(`.opt-row[data-id="${CSS.escape(id)}"]`);
    if (row) row.classList.toggle('selected', selectedIds.has(id));
    const check = document.querySelector(`.opt-row[data-id="${CSS.escape(id)}"] .checkbox[data-check]`);
    if (check) check.classList.toggle('checked', selectedIds.has(id));
    updateSelectedButtonState();
  }

  function clearSelection() {
    selectedIds.clear();
    document.querySelectorAll('#optimizerGroups .opt-row').forEach(c => c.classList.remove('selected'));
    document.querySelectorAll('#optimizerGroups .opt-row .checkbox').forEach(c => c.classList.remove('checked'));
    updateSelectedButtonState();
  }

  function updateSelectedButtonState() {
    const btn = document.getElementById('btnOptimizerSelected');
    if (!btn) return;
    const count = selectedIds.size;
    btn.disabled = count === 0;
    btn.innerHTML = count > 0
      ? '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>执行所选优化（' + count + '）'
      : '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>执行所选优化';
  }

  // 执行已勾选的优化项（支持跨分类；跳过当前页面分类之外的项需重新渲染时保持一致）
  async function runSelected() {
    if (batchRunning) return;
    const entries = displayList(OPTIONS).filter(o => selectedIds.has(o.id));
    if (!entries.length) {
      window.app?.toast('warning', '请先勾选要执行的优化项');
      return;
    }
    // 先收选择再报清单：虚拟卡要展开成用户实际选中的那一态，
    // 否则预览里写「Windows更新调整」、真正写的却是 NoAutoUpdate —— 承诺与动作分叉。
    const paramsByRun = await collectBatchChoices(entries);
    if (!paramsByRun) return;
    const batch = expandEntries(entries, paramsByRun);
    // M1（R1-1.8）：与 runBatch 同一条预检前置 —— 只治一条入口等于没治，
    // 用户从「执行所选」走仍然是第 5 项失败时前 4 项已落盘。
    const allowed = await filterByPreflight(batch);
    if (!allowed) return;
    if (!allowed.length) {
      window.app?.toast('warning', '勾选的优化项全部被预检拦下，没有可执行的项');
      return;
    }
    // 高危项统计
    const hazardList = allowed.filter(o => needsHazardConfirm(o));
    const highCount = allowed.filter(o => o.risk === 'high').length;
    const preview = allowed.slice(0, 12).map(o => '· ' + o.title).join('\n') +
      (allowed.length > 12 ? `\n…等共 ${allowed.length} 项` : '');
    // 含高风险项时整批走红色二次确认，警示文案由 dangerHint 结构化渲染
    const hasHazard = hazardList.length > 0;
    const ok = await window.app.confirm(
      '执行所选优化',
      `将依次执行已勾选的 ${allowed.length} 项优化（其中高风险 ${highCount} 项）：\n\n${preview}\n\n是否确认执行？`,
      '确认执行',
      '取消',
      (hasHazard || highCount > 0) ? {
        danger: true,
        dangerHint: hasHazard
          ? `其中包含 ${hazardList.length} 项高危安全操作（${hazardList.map(o => o.title).join('、')}），会显著降低系统安全防护。`
          : `包含 ${highCount} 项高风险优化，可能影响系统稳定性。`
      } : {}
    );
    if (!ok) return;

    // 高危项红色二次确认（2026-10-03 用户裁定由「逐个弹」改为「合并成一次」）。
    //
    // 原实现是 `for (const opt of hazardList) await confirmHazard(opt)` ——
    // 每项弹一个独立红色框。同一批里若有 3 项高危，用户要点 3 次「仍然执行」；
    // 而且**相邻两个框之间必然出问题**：前一个 resolve 后 focusTrap.release()
    // 把焦点抢回触发按钮，下一帧新框弹出并再次走 initialFocus，弹窗在视觉上
    // 「闪一下又闪一下」（用户实测反馈：确认框一闪而过、像是被自动拒绝）。
    //
    // 合并成一次后语义更强也更省事：把所有高危项点名列在同一个框里，用户一次看清
    // 「这批里到底有哪几项在降低安全防护」，一次表态。护栏没有变松 ——
    // 批量框本身已经是红色 danger（见上方 hasHazard 分支），这里只是不再重复 N 次。
    if (hazardList.length) {
      const detail = hazardList.map(o => {
        const sd = o.securityDegrade;
        return `· ${o.title}${sd && sd.why ? `（${sd.why}）` : ''}`;
      }).join('\n');
      const go = await window.app.confirmDanger(
        '⚠️ 高危安全操作确认',
        `本批 ${hazardList.length} 项高危优化会显著降低系统安全防护：\n\n${detail}`,
        '仍然全部执行',
        '取消',
        '此操作可能使系统更容易受到恶意软件或攻击的侵害，请确认已了解风险。'
      );
      if (!go) return;
    }

    if (!(await ensureRestorePoint())) return;

    batchRunning = true;
    const btn = document.getElementById('btnOptimizerSelected');
    if (btn) { btn.disabled = true; btn.dataset.orig = btn.innerHTML; btn.innerHTML = '执行中…'; }
    let okCount = 0, failCount = 0;
    const failedNames = [];
    // BoosterX §B2：整批只给**一次**生效建议，取成功项里最粗的档位。
    // 逐项提示会把用户推向「每改一项重启一次」；档位由后端侧表算好透在每行的 applyScope 上
    // （data/optimizer-scope.json，判定规则与档位序两侧同表，由 check-optimizer-dynamic 对拍）。
    let batchScope = 0, batchScopeCount = 0;
    for (let i = 0; i < allowed.length; i++) {
      const opt = allowed[i];
      // 审查 2026-09-27 M8：记录「当前 + 剩余」，提权确认瞬间据此持久化
      batchRemainingIds = allowed.slice(i).map(o => o.id);
      // 进度 Toast 由 runOptionActive 内部创建（此前这里先建一条、内部再建一条并销毁前者）
      progressToastSuffix = `${i + 1}/${allowed.length}`;
      try {
        const p = batchParams(opt, paramsByRun);
        if (p === null) { failCount++; failedNames.push(opt.title + '（未选定参数）'); continue; }
        const succeeded = await runOptionActive(p, opt);
        if (succeeded) {
          okCount++;
          const rank = SCOPE_RANK[String(opt.applyScope || 'none')] || 0;
          if (rank > batchScope) { batchScope = rank; batchScopeCount = 1; }
          else if (rank === batchScope && rank > 0) batchScopeCount++;
        }
        else { failCount++; failedNames.push(opt.title); }
      } catch (e) {
        failCount++; failedNames.push(opt.title);
      }
    }
    batchRemainingIds = null;
    progressToastSuffix = '';
    batchRunning = false;
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig; delete btn.dataset.orig; }
    clearSelection();
    renderGroups(OPTIONS); // 刷新已优化灰态
    window.app?.toast(
      okCount === allowed.length ? 'success' : 'warning',
      `执行完成：成功 ${okCount} 项，失败 ${failCount} 项` +
      (failCount ? `（${failedNames.slice(0, 5).join('、')}${failedNames.length > 5 ? ' 等' : ''}）` : '')
    );
    // 整批只提示一次生效粒度，且排在「执行完成」之后 —— 用户先要知道做没做成，再要知道要不要重启
    if (batchScope > 0 && batchScopeCount > 0) {
      window.app?.toast(batchScope >= SCOPE_RANK.reboot ? 'info' : 'success', scopeAdviceText(batchScope, batchScopeCount), 9000);
      window.app?.log('info', `优化批次生效粒度：${batchScope >= SCOPE_RANK.reboot ? '需重启电脑' : '建议重启资源管理器'}（${batchScopeCount} 项）`);
    }
  }

  // ==================== M1 批次整批预检 ====================
  //
  // 判据在 Rust 侧 `preflight_reason`，与 optimizer_run 单条执行链**同一个函数**
  // （`commands/optimizer/apply.rs`）。这里只负责「问一次 + 把结果说清楚」。
  //
  // 返回语义（三态，勿改）：
  //   null        → 用户取消或通道缺席，调用方必须**中止整批**（不是「按原样执行」）
  //   []          → 全被拦，调用方提示「无可执行项」并中止
  //   [可执行项] → 允许继续
  async function filterByPreflight(batch) {
    if (!batch.length) return batch;
    const ids = batch.map(o => o.id);
    let res;
    try {
      // 批量入口都是正向执行（还原是另一条路径），restore 恒 false —— 与服务端
      // 「高危确认在还原方向豁免」的语义一致，两边不许各传各的。
      res = await window.api?.optimizer?.batchPreflight?.(ids, false);
    } catch (e) {
      // R1-1.9：通道缺席 / IPC reject 必须**说清**，不许静默无反应。
      // 这里选择中止而非放行：预检是 fail-closed 准入，放行等于退回逐条 await 的旧行为。
      window.app?.toast('error', '整批预检失败（通道不可用），已中止本批，未执行任何项', 7000);
      window.app?.log('error', `批量预检失败: ${e && e.message ? e.message : e}`);
      return null;
    }
    if (!res || res.success !== true) {
      window.app?.toast('error', '整批预检未通过（' + ((res && res.message) || '无回执') + '），已中止本批', 7000);
      return null;
    }
    const rejected = Array.isArray(res.rejected) ? res.rejected : [];
    if (!rejected.length) return batch;
    const allowed = new Set(Array.isArray(res.runnable) ? res.runnable : []);
    // 只保留后端点名 runnable 的项。后端少给一项我们就少跑一项，不自己乐观补齐 ——
    // 「预检说能跑」和「实际会跑」必须是同一个集合。
    const kept = batch.filter(o => allowed.has(o.id));
    const titleOf = id => batch.find(o => o.id === id)?.title || id;
    const detail = rejected
      .slice(0, 10)
      .map(r => '· ' + titleOf(r.id) + '：' + r.reason)
      .join('\n') + (rejected.length > 10 ? `\n…等共 ${rejected.length} 项被拦` : '');
    const go = await window.app.confirm(
      '部分优化项无法执行',
      `整批预检拦下 ${rejected.length} 项：\n\n${detail}\n\n是否只执行剩下的 ${kept.length} 项？`,
      '只执行可执行项',
      '取消整批'
    );
    if (!go) return null;
    if (kept.length) {
      window.app?.log('info', `批量预检拦下 ${rejected.length} 项：${rejected.map(r => `${r.id}(${r.reason})`).join(', ')}`);
    }
    return kept;
  }

  // ==================== 一键全选当前页并依次执行 ====================
  function getCurrentPageOptions() {
    const list = displayList(OPTIONS);   // 虚拟卡顶掉被聚合的真实项，与界面所见同一份清单
    if (activeCategory === '全部') return list;
    return list.filter(o => displayGroup(o) === activeCategory);
  }

  function setCardsSelected(sel) {
    // 全选执行时的临时视觉高亮（与部分选择的 .selected 勾选态区分，避免互相覆盖）
    document.querySelectorAll('#optimizerGroups .opt-row').forEach(c => {
      c.classList.toggle('batch-selected', sel);
    });
  }

  let batchRunning = false;
  async function runBatch() {
    if (batchRunning) return;
    const entries = getCurrentPageOptions();
    if (!entries.length) {
      window.app?.toast('warning', '当前页面没有可执行的优化项');
      return;
    }
    // 与 runSelected 同一条前置闸：多态卡与 dynamic 项先让用户表态，取消即整批中止
    const paramsByRun = await collectBatchChoices(entries);
    if (!paramsByRun) return;
    const batch = expandEntries(entries, paramsByRun);
    // M1（R1-1.8）：整批预检**先于**任何确认弹窗与执行。原先第 5 项失败时前 4 项已落盘，
    // 现在把「哪几项会被拦、为什么」提前告知，用户一次决定。
    //
    // 预检只读、不改系统状态，所以拦下的项不会留下半成品。确认后才执行（用户可以
    // 选择「仍然执行可执行的那部分」——被拦的项会被剔出批次，不会白等）。
    const allowed = await filterByPreflight(batch);
    if (!allowed) { setCardsSelected(false); return; }
    if (!allowed.length) {
      window.app?.toast('warning', '本批全部优化项都被预检拦下，没有可执行的项');
      setCardsSelected(false);
      return;
    }
    // 全选高亮，提示即将执行的项
    setCardsSelected(true);
    const highCount = allowed.filter(o => o.risk === 'high').length;
    const hazardList = allowed.filter(o => needsHazardConfirm(o));
    const preview = allowed.slice(0, 12).map(o => '· ' + o.title).join('\n') +
      (allowed.length > 12 ? `\n…等共 ${allowed.length} 项` : '');
    // 含高风险项时整批走红色二次确认，警示文案由 dangerHint 结构化渲染
    const ok = await window.app.confirm(
      '批量执行优化',
      `将依次执行当前页全部 ${allowed.length} 项优化（其中高风险 ${highCount} 项）：\n\n${preview}\n\n是否确认执行？`,
      '确认执行',
      '取消',
      (hazardList.length > 0 || highCount > 0) ? {
        danger: true,
        dangerHint: hazardList.length > 0
          ? `其中包含 ${hazardList.length} 项高危安全操作（${hazardList.map(o => o.title).join('、')}），会显著降低系统安全防护。`
          : `包含 ${highCount} 项高风险优化，可能影响系统稳定性。`
      } : {}
    );
    if (!ok) { setCardsSelected(false); return; }

    // 高危项红色二次确认（与「执行所选」链同一裁定：合并成一次，不逐个弹）
    // 逐个弹的害处见 runBatch 处注释：要连点 N 次「仍然执行」，且相邻两框之间
    // focusTrap 的焦点归还会造成视觉上「框闪一下」。这里点名列出，一次表态。
    if (hazardList.length) {
      const detail = hazardList.map(o => {
        const sd = o.securityDegrade;
        return `· ${o.title}${sd && sd.why ? `（${sd.why}）` : ''}`;
      }).join('\n');
      const go = await window.app.confirmDanger(
        '⚠️ 高危安全操作确认',
        `本页 ${hazardList.length} 项高危优化会显著降低系统安全防护：\n\n${detail}`,
        '仍然全部执行',
        '取消',
        '此操作可能使系统更容易受到恶意软件或攻击的侵害，请确认已了解风险。'
      );
      if (!go) { setCardsSelected(false); return; }
    }

    // 批次含「禁用 70+ 非必要服务」时：单独弹窗询问是否连商店相关服务一并禁用（一次询问作用于整批）
    let batchIncludeStore = false;
    if (allowed.some(o => o.id === 'tf_svc_bulk')) {
      batchIncludeStore = await confirmIncludeStoreServices();
    }

    // 执行前统一检查系统还原点（未创建/超 5 天弹警示；用户最终拒绝则中止）
    if (!(await ensureRestorePoint())) { setCardsSelected(false); return; }

    batchRunning = true;
    const btn = document.getElementById('btnOptimizerBatch');
    if (btn) { btn.disabled = true; btn.dataset.orig = btn.innerHTML; btn.innerHTML = '批量执行中…'; }
    let okCount = 0, failCount = 0;
    const failedNames = [];
    let batchScope = 0, batchScopeCount = 0;
    for (let i = 0; i < allowed.length; i++) {
      const opt = allowed[i];
      // 审查 2026-09-27 M8：同 runSelected——提权中断时据此恢复剩余批次
      batchRemainingIds = allowed.slice(i).map(o => o.id);
      // 进度 Toast 由 runOptionActive 内部创建（同上，消除每项一次白建白毁）
      progressToastSuffix = `${i + 1}/${allowed.length}`;
      try {
        const p = opt.id === 'tf_svc_bulk'
          ? { includeStore: !!batchIncludeStore }
          : batchParams(opt, paramsByRun);
        if (p === null) { failCount++; failedNames.push(opt.title + '（未选定参数）'); continue; }
        const succeeded = await runOptionActive(p, opt);
        if (succeeded) {
          okCount++;
          const rank = SCOPE_RANK[String(opt.applyScope || 'none')] || 0;
          if (rank > batchScope) { batchScope = rank; batchScopeCount = 1; }
          else if (rank === batchScope && rank > 0) batchScopeCount++;
        }
        else { failCount++; failedNames.push(opt.title); }
      } catch (e) {
        failCount++; failedNames.push(opt.title);
      }
    }
    batchRemainingIds = null;
    progressToastSuffix = '';
    batchRunning = false;
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig; delete btn.dataset.orig; }
    setCardsSelected(false);
    clearSelection();
    renderGroups(OPTIONS); // 刷新已优化灰态
    window.app?.toast(
      okCount === allowed.length ? 'success' : 'warning',
      `批量执行完成：成功 ${okCount} 项，失败 ${failCount} 项` +
      (failCount ? `（${failedNames.slice(0, 5).join('、')}${failedNames.length > 5 ? ' 等' : ''}）` : '')
    );
    // 与 runSelected 同一口径：两条批量入口都只提示一次，漏一条会让「一键全选」比手勾更没有提示
    if (batchScope > 0 && batchScopeCount > 0) {
      window.app?.toast(batchScope >= SCOPE_RANK.reboot ? 'info' : 'success', scopeAdviceText(batchScope, batchScopeCount), 9000);
      window.app?.log('info', `优化批次生效粒度：${batchScope >= SCOPE_RANK.reboot ? '需重启电脑' : '建议重启资源管理器'}（${batchScopeCount} 项）`);
    }
  }

  // ==================== 初始化 ====================
  // C2（2026-09-14 重复点审查）：按系统盘介质显隐预读相关选项 ——
  //   SSD 隐藏「加快预读能力改善速度」(perf_prefetcher_fast)：SSD 上 Prefetch 收益低，不该再开预读；
  //   HDD 隐藏「关闭预读」(prefetch_off)：HDD 依赖预读，关掉反而变慢。
  //   探测失败或介质未知 → 两边都不隐藏，绝不因探测失败藏掉用户要用的选项。
  const HIDE_ON_SSD = ['perf_prefetcher_fast'];
  // 优化中心目录里当前没有「关闭预读」项（历史上曾引用的 prefetch_off 已不在 OPTIONS 中），
  // 因此 HDD 侧在优化中心无项可隐藏 —— HDD 的预读差异体现在磁盘清理的 Prefetch 条目上。
  // 将来若新增「关闭预读」项，把其 id 填进这个数组即可。
  const HIDE_ON_HDD = [];
  let diskType = null;       // { media, busType, isSsd, known, detector } | null
  function filterByDiskType(list) {
    if (!diskType || !diskType.known) return list;
    const drop = new Set(diskType.isSsd ? HIDE_ON_SSD : HIDE_ON_HDD);
    return list.filter(o => !drop.has(o.id));
  }

  function init() {
    if (window.api?.optimizer) {
      // 磁盘介质探测与目录拉取并行；探测失败不阻塞清单渲染
      const pDisk = window.api.system?.diskType
        ? window.api.system.diskType().then(r => (r && r.success ? r.data : null)).catch(() => null)
        : Promise.resolve(null);
      // E7：先取分类侧表，再取目录 —— 渲染要用分组口径决定每项归到哪个看板。
      // 两条并行取（互不依赖），侧表失败不阻塞目录渲染（走 GROUP_FALLBACK 兜底）。
      Promise.all([pDisk, window.api.optimizer.list(), window.api.optimizer.listGroups()])
        .then(([dt, res, gs]) => {
        diskType = dt;
        // E7：分类两层结构。失败/形状不对时保留 GROUP_FALLBACK（applyGroupSidecar 内部已判）
        if (gs && gs.success) applyGroupSidecar(gs.data);
        if (res && res.success && Array.isArray(res.data)) {
          OPTIONS = filterByDiskType(res.data);
          activeCategory = getSavedCategory();
          // 审查 v3：本地执行记录必须在渲染之前载入，否则首屏会短暂显示「未优化」，
          // 用户在这一瞬勾选并重复执行——正是本次要防的形态。
          loadAppliedLocal();
          renderCatNav();
          setCategory(activeCategory);
          bindEvents();
          // 安全托底：异步批量检测注册表项是否已优化（不阻塞首屏，结果回来后增量灰化）
          startOptimizedCheck();
          // v2.6.0（P0-1）：启动扫描已应用记账 + 未完成还原横幅 + 退役迁移结果回报
          loadStateOverview();
          // 审查 2026-09-27 M8：恢复上次因提权重启中断的批量勾选
          restorePendingBatch();
        }
      }).catch(() => renderFallback());
      window.api.optimizer.onProgress(({ percent }) => {
        if (typeof percent === 'number') setProgressToastProgress(percent);
      });
    } else {
      renderFallback();
    }

    const checkAdmin = () => {
      const st = window.app?.getState?.();
      if (!st) return;
      if (st.isAdmin === false) showAdminWarning();
      else if (st.isAdmin === true && document.getElementById('btnOptimizerElevate')) {
        document.getElementById('btnOptimizerElevate').style.display = 'none';
        const b = document.getElementById('optimizerBanner'); if (b) b.style.display = 'none';
      }
    };
    setTimeout(checkAdmin, 400);
    setTimeout(checkAdmin, 1200);
    // v3.2.0：弹窗 Esc 关闭已由 modal.js 工厂统一接管，无需模块自绑 keydown
  }

  function showAdminWarning() {
    const btn = document.getElementById('btnOptimizerElevate');
    const banner = document.getElementById('optimizerBanner');
    if (btn) btn.style.display = '';
    if (banner) {
      banner.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2L1 21h22L12 2zm1 15h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>' +
        '<span>当前不是管理员权限：注册表(HKLM)与系统服务等选项将无法生效。建议点击右上角「提升权限」以管理员身份重启。</span>';
      banner.style.display = 'flex';
    }
  }

  function renderFallback() {
    renderCatNav(); // 浏览器预览模式下也渲染分类栏，保持布局一致
    const root = document.getElementById('optimizerGroups');
    if (root) root.innerHTML = window.emptyState
      ? window.emptyState({ icon: 'search', title: '优化选项需在应用内运行', desc: '当前为浏览器预览模式，请在 Electron 应用内打开「电脑优化中心」使用全部功能' })
      : `<div class="empty-state"><p>当前为浏览器预览模式，优化选项需在 Electron 应用内运行。</p></div>`;
  }

  function bindEvents() {
    const root = document.getElementById('optimizerGroups');
    if (!root) return;

    // 看板行点击打开弹窗；点击勾选框仅切换选择状态；列底「全选本类」批量勾选；
    // 已优化（灰态）行点击 → 弹「是否还原此项优化？」确认
    root.addEventListener('click', async (e) => {
      const check = e.target.closest('.checkbox[data-check]');
      if (check) {
        e.stopPropagation();
        const id = check.dataset.check;
        if (id) toggleSelect(id);
        return;
      }
      const selAll = e.target.closest('.opt-col-selectall');
      if (selAll) {
        const group = selAll.dataset.selectallGroup;
        // 用 displayList：虚拟卡要能被「全选本类」选中，被聚合的真实项则不能（它们已不在界面上）
        const ids = displayList(OPTIONS).filter(o => displayGroup(o) === group && !optimizedIds.has(o.id)).map(o => o.id);
        ids.forEach(id => selectedIds.add(id));
        renderGroups(OPTIONS);
        window.app?.toast('info', `已全选「${group}」${ids.length} 项，可点击「执行所选优化」批量执行`);
        return;
      }
      // 「更多调优项」→ 打开外设优化独立窗口
      const moreBtn = e.target.closest('.opt-col-more');
      if (moreBtn) {
        if (window.api?.peripheralWindow?.openWindow) {
          window.api.peripheralWindow.openWindow().catch(function (e) { window.app?.toast?.('error', '外设优化窗口打开失败：' + ((e && e.message) || e)); });
        } else {
          window.app?.toast('info', '外设优化窗口需在 Trim 应用内打开');
        }
        return;
      }
      const row = e.target.closest('.opt-row');
      if (!row) return;
      const id = row.dataset.id;
      const o = findEntry(id);   // 虚拟卡不在 OPTIONS 里
      if (!o) return;
      if (optimizedIds.has(o.id)) {
        // 安全兜底：已生效项点击 → 打开详情弹窗（按钮为「立即恢复」，见 openModal）
        openModal(o);
        return;
      }
      openModal(o);
    });

    // v3.2.0：弹窗按钮（立即执行/恢复/还原/AI）绑定已随 openModal 实例化，init 不再预绑
    // （还原入口 restoreOption 仍为模块级，弹窗与 stale 横幅共用，见文件上方定义）

    const elevateBtn = document.getElementById('btnOptimizerElevate');
    if (elevateBtn) {
      elevateBtn.addEventListener('click', async () => {
        const ok = await window.app.requestElevation('优化电脑部分选项需要管理员权限才能修改系统注册表与服务。');
        if (!ok) window.app.toast('info', '已取消提权，仅可执行无需提升权限的选项');
      });
    }

    // 审查 v2-M22（v1 L13 点名的 optimizer 开窗/执行入口）：runBatch/runSelected 是 async，
    // 循环体内部虽有 try/catch，但**循环之前**的 confirmDanger / ensureRestorePoint 一旦 reject
    // 就是浮动 Promise —— 表现为「点批量执行毫无反应」，日志里也查不到。统一在此收口。
    const guardBatch = (fn) => () => {
      if (!window.api?.optimizer) { window.app?.toast('warning', '当前为预览模式，无法执行优化'); return; }
      Promise.resolve(fn()).catch((e) => {
        window.app?.toast('error', '批量执行异常：' + ((e && e.message) || e));
        window.app?.log?.('error', '优化批量执行异常: ' + ((e && e.message) || e));
      });
    };

    const batchBtn = document.getElementById('btnOptimizerBatch');
    if (batchBtn) batchBtn.addEventListener('click', guardBatch(runBatch));
    const selectedBtn = document.getElementById('btnOptimizerSelected');
    if (selectedBtn) {
      selectedBtn.disabled = true;
      selectedBtn.addEventListener('click', guardBatch(runSelected));
    }
    // 分类切换时保留勾选状态（跨分类勾选允许执行所选）
    updateSelectedButtonState();
  }

  window.optimizer = { init, setCategory };
})();
