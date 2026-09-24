// optimizer.js - 优化电脑模块
// 渲染由 optimizer:list 拉取的选项目录为分组胶囊卡片；
// 卡片宽度按窗口自适应：非最大化一行 3 条，最大化一行 6 条；
// 点击卡片弹出详情弹窗（优缺点 + 详细操作 + 执行/还原/AI），背景模糊遮罩；
// 点击空白/遮罩、ESC 键即可关闭弹窗。
// 执行仍通过 main 进程后台静默执行，实时进度以主界面右上角 Toast 展示。
(function () {
  'use strict';

  const GROUP_ORDER = ['内存优化', '性能调优', '音频优化', '外设调优', '桌面体验', '任务调度', '系统服务', '隐私防护', '系统调校', '系统精简', '显卡优化', '浏览器优化'];
  const RISK_TEXT = { low: '低风险', medium: '中风险', high: '高风险' };

  // 旧分组 → 新分类重映射（Trim 分类风格：启动与响应→系统调校、游戏与多媒体→性能调优、键鼠与外设→外设调优、安全与隐私→隐私防护）
  const GROUP_MAP = {
    '启动与响应': '系统调校',
    '游戏与多媒体': '性能调优',
    '安全与隐私': '隐私防护',
    '系统清理': '系统精简',
    '显卡优化': '显卡优化',
    '键鼠与外设': '外设调优',
    '系统精简': '系统精简'
  };
  // 系统服务与内存 按条目拆分到「内存优化」/「系统服务」
  const ITEM_GROUP_OVERRIDE = {
    svc_mem_gb: '内存优化', tf_mmagent: '内存优化',
    tf_svc_bulk: '系统服务', tf_drv_disable: '系统服务'
  };

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
  const GROUP_COLORS = {
    '系统调校': 'linear-gradient(135deg, #6B46C1, #553C9A)',
    '性能调优': 'linear-gradient(135deg, #16A34A, #15803D)',
    '内存优化': 'linear-gradient(135deg, #D97706, #B45309)',
    '隐私防护': 'linear-gradient(135deg, #DC2626, #B91C1C)',
    '显卡优化': 'linear-gradient(135deg, #7C3AED, #6D28D9)',
    '外设调优': 'linear-gradient(135deg, #0D9488, #0F766E)',
    '音频优化': 'linear-gradient(135deg, #EC4899, #BE185D)',
    '桌面体验': 'linear-gradient(135deg, #14B8A6, #0F766E)',
    '任务调度': 'linear-gradient(135deg, #8B8EE0, #6366C9)',
    '系统服务': 'linear-gradient(135deg, #8B5CF6, #7C3AED)',
    '系统精简': 'linear-gradient(135deg, #475569, #334155)',
    '浏览器优化': 'linear-gradient(135deg, #0EA5E9, #0284C7)',
    '游戏安全诊断': 'linear-gradient(135deg, #EF4444, #B91C1C)'
  };
  const GROUP_ACCENT = {
    '系统调校': '#6B46C1',
    '性能调优': '#16A34A',
    '内存优化': '#D97706',
    '隐私防护': '#DC2626',
    '显卡优化': '#7C3AED',
    '外设调优': '#0D9488',
    '音频优化': '#EC4899',
    '桌面体验': '#14B8A6',
    '任务调度': '#8B8EE0',
    '系统服务': '#8B5CF6',
    '系统精简': '#475569',
    '浏览器优化': '#0EA5E9',
    '游戏安全诊断': '#EF4444'
  };

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
  // 以下项会显著削弱系统安全防护，执行前必须弹红色警示确认
  const HAZARD_OPTION_IDS = new Set([
    'disable_uac',           // 禁用 UAC
    'tf_defender',           // 关闭 Defender 与 SmartScreen
    'tf_microcode_del',      // 删除 CPU 微码 DLL
    'spectre_off',           // 关闭幽灵/熔断缓解
    'perf_vbs_off',          // 关闭 VBS / 内存完整性
    'perf_exploit_protection_off', // 关闭 Exploit Protection（乱序内存）
    'tf_svc_bulk',           // 禁用 70+ 非必要服务（含安全服务）
    'tf_drv_disable',        // 禁用高风险驱动服务
    'perf_windows_update_off' // v3.7.0 P1：彻底禁用 Windows 更新（安全补丁不再送达）
  ]);

  // 执行前高危确认：返回 true 继续 / false 取消
  async function confirmHazard(opt) {
    if (!HAZARD_OPTION_IDS.has(opt.id)) return true;
    // 红色二次确认：警示文案走 dangerHint 结构化字段，由弹窗模板渲染
    return window.app.confirmDanger(
      '⚠️ 高危安全操作确认',
      `「${opt.title}」会显著降低系统安全防护：\n\n· ${opt.desc || ''}`,
      '仍然执行',
      '取消',
      '此操作可能使系统更容易受到恶意软件或攻击的侵害，请确认已了解风险。'
    );
  }

  // ==================== 工具 ====================
  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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
    if (s.pwsh) return '执行 PowerShell 内联脚本';
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
  const OPT_CATEGORIES = ['全部', '内存优化', '性能调优', '音频优化', '外设调优', '桌面体验', '任务调度', '系统服务', '隐私防护', '系统调校', '系统精简', '显卡优化', '浏览器优化', '游戏安全诊断'];

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
      const accent = GROUP_ACCENT[group] || 'var(--accent)';
      // 分类色实底（hex）配白字；accent 兜底时走 --accent-text 自动适配明暗主题对比度
      const colFg = accent.startsWith('#') ? '#FFFFFF' : 'var(--accent-text)';
      const items = byGroup[group];
      // 外设调优：列头提供「更多调优项」入口 → 打开外设优化窗口（Win32PrioritySeparation 等深度调优）
      const moreBtn = group === '外设调优'
        ? `<button type="button" class="opt-col-more" data-more-group="外设调优" data-tip="打开外设优化：处理器调度 / 键盘注册表 / 鼠标队列深度调优">更多调优项</button>`
        : '';
      return `
      <section class="opt-col" style="--c:${accent};--cf:${colFg}">
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
    // ancel 对比审查 P1（2026-09-14）：网络栈优化（TCP/拥塞控制/RSS 等）已从优化中心
    // 迁至维护中心（maintenance-scripts.js），此处加轻量指引避免用户在优化中心找不到。
    const tip = document.getElementById('optimizerNetHint');
    if (tip) {
      tip.innerHTML = `<span class="pw-last-scan" data-tip="网络栈优化已迁至维护中心">网络栈优化（TCP/拥塞控制/RSS/RSC/ECN 等）已移至「系统维护」页</span><button type="button" class="btn btn-ghost btn-xs" id="btnGoMaintenanceNet" data-tip="前往维护中心">前往维护中心</button>`;
      const btn = tip.querySelector('#btnGoMaintenanceNet');
      if (btn) btn.addEventListener('click', () => {
        const nav = document.querySelector('.nav-item[data-page="maintenance"]');
        if (nav) nav.click();
      });
    }
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
  function renderOptRow(o, index) {
    const id = escapeHtml(o.id);
    const isOpt = optimizedIds.has(o.id);
    return `
      <div class="opt-row${isOpt ? ' optimized' : ''}" data-id="${id}" data-tip="${isOpt ? '该项优化已生效，点击可还原' : '点击查看「' + escapeHtml(o.title) + '」详情'}">
        <div class="checkbox${selectedIds.has(o.id) ? ' checked' : ''}${isOpt ? ' disabled' : ''}" data-check="${id}" data-tip="${isOpt ? '已优化的项不可勾选，点击行可还原' : '勾选/取消选择该优化项'}"></div>
        <span class="opt-row-index">${index}</span>
        <span class="opt-row-name">${escapeHtml(o.title)}</span>
        ${riskBadge(o.risk)}${isOpt ? '<span class="opt-row-opttag">已优化</span>' : ''}
      </div>`;
  }

  // ==================== 安全托底：已优化检测与还原 ====================
  // 启动时异步批量检测含注册表操作的项是否已生效（不阻塞首屏），命中项灰态展示；
  // 点击灰态行弹「是否还原此项优化？」确认，「是」执行 restore 后恢复正常态。
  const optimizedIds = new Set();

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

  // 已优化项标记：执行成功后立即置灰（用于用户刚操作完的即时反馈）。
  // 判断规则：
  //   · dynamic 项（如 SVCHost 内存阈值）一定生效 → 直接标记
  //   · 含 reg 步骤 / 含 service.disable 步骤 → 标记
  //   · 含 pwsh / cmd 步骤（绝大多数是注册表、服务或系统级改动）→ 标记
  // 兜底：只要执行成功就认为"已优化"，避免漏判导致用户看不到灰态反馈。
  function markOptimizedIfApplicable(opt) {
    if (!opt || !opt.id) return false;
    if (opt.dynamic) { optimizedIds.add(opt.id); return true; }
    const steps = Array.isArray(opt.steps) ? opt.steps : [];
    if (steps.length === 0) return false;
    optimizedIds.add(opt.id);
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
          optimizedIds.add('svc_mem_gb');
          applyOptimizedStyles();
        }
      }).catch(() => {});
    }
    if (!checkIds.length) return;
    window.api.optimizer.checkOptimized(checkIds).then(resp => {
      if (resp && resp.success && resp.results) {
        // v2.7.0：实时检测结果为权威源——与持久化缓存不一致时以本轮为准（增删灰态都生效）
        for (const id of checkIds) {
          if (resp.results[id] === true) optimizedIds.add(id);
          else optimizedIds.delete(id);
        }
        applyOptimizedStyles();
      }
    }).catch(() => { /* 检测失败不影响正常使用 */ });
  }

  // 还原入口统一走这里：优先按执行前记录的注册表值恢复；
  // 无备份记录时回退到优化项预置的还原脚本。
  // v2.6.0（P0-1）：提升到模块级，供详情弹窗与「未完成还原」横幅一键还原共用。
  async function restoreOption(opt) {
    if (window.api?.optimizer?.restoreReg) {
      let r = null;
      try { r = await window.api.optimizer.restoreReg(opt.id); } catch (e) { /* 走回退 */ }
      if (r && r.success) {
        optimizedIds.delete(opt.id);
        renderGroups(OPTIONS);
        window.app?.toast('success', '已恢复：' + (opt.title || opt.id));
        return true;
      }
      if (r && !r.missing) {
        window.app?.log('warn', `按备份还原失败（回退预置脚本）: ${opt.title || opt.id}: ${r.message || ''}`);
      }
    }
    const okRun = await runOptionActive({ restore: true }, opt);
    if (okRun) {
      optimizedIds.delete(opt.id);
      renderGroups(OPTIONS);
      window.app?.toast('success', '已恢复：' + (opt.title || opt.id));
    }
    return okRun;
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
      // v2.7.0：主进程首启扫描的持久化结果先灰化（页面未到、扫描未跑完时也有即时反馈）；
      // startOptimizedCheck 的实时检测稍后权威校正。动态项（svc_mem_gb）走注册表实时档位，不在此列。
      const detected = resp.detected || {};
      let prefill = 0;
      for (const [id, d] of Object.entries(detected)) {
        const opt = OPTIONS.find(o => o.id === id);
        if (!opt || opt.dynamic) continue;
        if (d && d.optimized === true && !optimizedIds.has(id)) { optimizedIds.add(id); prefill++; }
      }
      if (prefill) applyOptimizedStyles();
      // 退役迁移（P0-3）结果一次性回报
      const mig = resp.migration;
      if (mig && Array.isArray(mig.restored) && mig.restored.length) {
        window.app?.toast('success', `已自动还原 ${mig.restored.length} 项已退役优化的历史改动`);
      }
      if (mig && Array.isArray(mig.failed) && mig.failed.length) {
        window.app?.log('warn', `${mig.failed.length} 项退役优化的历史改动还原失败（多为缺管理员权限），下次启动自动重试`);
      }
      const staleIds = (Array.isArray(resp.staleIds) ? resp.staleIds : []).filter(id => OPTIONS.some(o => o.id === id));
      if (staleIds.length) showStaleBanner(staleIds);
    } catch (e) { /* 状态总览失败不影响正常使用 */ }
  }

  function showStaleBanner(ids) {
    const banner = document.getElementById('optimizerStaleBanner');
    const text = document.getElementById('optimizerStaleText');
    if (!banner || !text) return;
    const names = ids.slice(0, 3).map(id => getOptionTitle(id)).join('、') + (ids.length > 3 ? ` 等 ${ids.length} 项` : '');
    text.textContent = `检测到 ${ids.length} 项优化改动未完成还原（${names}）：可能因执行中断或被系统回写导致状态不明。`;
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
  }

  // ==================== 详情弹窗（v3.2.0 弹窗统一批次：迁移到 modal.js 工厂） ====================
  // 旧 opt-modal-* 自建骨架已删除；现在走 window.modal.create() 统一三段式
  // （usage-backdrop > usage-modal，含唯一 id / 焦点陷阱 / Esc 与遮罩关闭 / IPC 日志）。
  // 图1 专属视觉保留：齿轮图标 accent 着色、优缺点绿红双列、footer 左侧内存档位提示位。
  let optModal = null;     // 当前弹窗 ctrl（modal.create 返回值）
  let activeOption = null;

  function openModal(o, notice) {
    // 重复打开（如执行后刷新按钮态）先关旧实例，保证唯一 id 与事件不叠加
    if (optModal) { optModal.close(); optModal = null; }
    activeOption = o;
    const accent = GROUP_ACCENT[displayGroup(o)] || 'var(--accent)';
    const stepCount = (o.steps || []).length;
    const iconStyle = `style="background:${accent}18;color:${accent}"`;
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
      </div>`;
    const footerHtml = `
      <div class="opt-detail-mem" style="display:none"></div>
      <span class="model-picker-spacer"></span>
      <button class="btn btn-opt-ai opt-btn-ai">AI 生成优缺点</button>
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
    // 分类强调色注入弹窗（既有行为：分类色着色 icon/徽章，较深分类色配白字）
    if (accent.startsWith('#')) {
      optModal.modal.style.setProperty('--accent', accent);
      optModal.modal.style.setProperty('--accent-text', '#FFFFFF'); // 分类色均较深，白字 ≥ 4.5:1
    } else {
      optModal.modal.style.removeProperty('--accent');
      optModal.modal.style.removeProperty('--accent-text'); // accent 兜底时沿用主题自动前景
    }
    const $ = (sel) => optModal.modal.querySelector(sel);
    $('.opt-detail-desc').textContent = o.desc || '（无描述）';
    $('.opt-detail-effect').textContent = effectHint;
    $('.opt-col-pros').textContent = o.pros || '暂缺，可点击下方「AI 生成优缺点」重新生成。';
    $('.opt-col-cons').textContent = o.cons || '暂缺，可点击下方「AI 生成优缺点」重新生成。';
    $('.opt-detail-steps-wrap').innerHTML = renderSteps(o.steps);

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
        notice = canRestore
          ? '您已完成优化。点击「立即恢复」将删除对应的注册表修改，恢复系统默认状态。'
          : '您已完成优化，该项暂不提供恢复功能';
      }
    } else if (!o.dynamic) {
      runBtn.textContent = '立即执行';
      runBtn.disabled = false;
      runBtn.dataset.mode = 'run';
    }
    // 安全兜底提示条：在按钮态确定后渲染（notice 由上方分支生成）
    const noticeEl = $('.opt-detail-notice');
    if (notice) {
      noticeEl.textContent = notice;
      noticeEl.style.display = 'block';
    }

    // 动态 / 还原：footer 左侧内存档位提示位（图1 专属视觉，保留）
    const memWrap = $('.opt-detail-mem');
    const restoreBtn = $('.opt-btn-restore');
    if (o.dynamic) {
      memWrap.style.display = '';
      memWrap.innerHTML = '<select class="field-input optimizer-mem-select opt-mem-select" data-tip="选择内存大小或重置">' +
        MEMORY_OPTIONS.map(m => `<option value="${m.gb}">${m.label}</option>`).join('') + '</select>';
      const sel = memWrap.querySelector('.opt-mem-select');
      // 根据下拉档位实时刷新优缺点与步骤显示
      function updateMemVariant() {
        const gb = sel.value;
        const info = MEM_PROS_CONS[gb] || MEM_PROS_CONS[8];
        $('.opt-col-pros').textContent = info.pros;
        $('.opt-col-cons').textContent = info.cons;
        // 步骤区：显示当档位对应的执行说明
        const label = (gb === 'default') ? '重置为默认值' : (gb + ' GB');
        $('.opt-detail-steps-wrap').innerHTML =
          `<ol class="opt-detail-steps"><li><span class="opt-detail-step-label">SVCHost 拆分阈值 ${label}</span>` +
          `<code class="opt-detail-step-note">reg add HKLM\\SYSTEM\\ControlSet001\\Control /v SvcHostSplitThresholdInKB /t REG_DWORD /d … /f</code></li></ol>`;
        $('.opt-detail-count').textContent = '1 步操作';
      }
      // 档位联动按钮态：当前已应用的档位 → 置灰（无后续操作）；
      // 选择其他档位 → 启用「立即执行」，可直接应用。
      function syncRunBtnForGear() {
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
      sel.addEventListener('change', () => { updateMemVariant(); syncRunBtnForGear(); });
      // 初始档位：优先选中当前已应用的档位（未优化时默认 8，与后端默认对齐）
      sel.value = (svcAppliedGb != null) ? String(svcAppliedGb) : '8';
      updateMemVariant();
      syncRunBtnForGear();
      // 兜底：弹窗打开后异步刷新一次注册表实际档位（防止启动检测尚未返回）
      if (o.id === 'svc_mem_gb' && window.api?.optimizer?.svcMemCurrent) {
        window.api.optimizer.svcMemCurrent().then(r => {
          if (!r || !r.success) return;
          if (activeOption !== o) return; // 弹窗已切走，丢弃
          svcAppliedGb = r.gb;
          if (r.gb != null) {
            optimizedIds.add(o.id);
            applyOptimizedStyles();
          }
          sel.value = (r.gb != null) ? String(r.gb) : sel.value;
          updateMemVariant();
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
      const go = await confirmHazard(opt);
      if (!go) return;
      // R3（v3.6.6 M1）：dynamic 项的下拉值必须在 closeOptModal 之前读取，
      // 否则 optModal 被置 null 后 querySelector 恒返回 undefined → 任何档位都回落 8GB。
      let preCloseGbVal = null;
      if (opt.dynamic) {
        const selEl = optModal?.modal?.querySelector('.opt-mem-select');
        preCloseGbVal = selEl ? Number(selEl.value) || 8 : 8;
      }
      // 立即执行后自动关闭弹窗
      closeOptModal();
      // tf_svc_bulk：单独弹窗询问是否连商店相关服务一并禁用（用户选择经 params 传递）
      const includeStore = opt.id === 'tf_svc_bulk' ? await confirmIncludeStoreServices() : false;
      // 执行前检查系统还原点（警示/风险确认；用户最终拒绝则不执行）。
      // tf_restore_point 本身就是创建动作，再走检查会「先弹建议创建、再重复创建」，直接放行。
      if (opt.id !== 'tf_restore_point' && !(await ensureRestorePoint())) return;
      if (opt.dynamic) {
        const gbVal = preCloseGbVal ?? 8;
        // 本会话立即记录已应用档位：重开弹窗时该档位按钮置灰
        svcAppliedGb = gbVal;
        // B11：与 runBatch 对齐 —— await + try/catch，避免浮动 Promise 变成
        // unhandled rejection（用户侧表现为「点击后毫无反应」）
        try {
          await runOptionActive({ gb: gbVal }, opt);
        } catch (e) {
          window.app?.toast('error', '优化执行失败: ' + (e.message || e));
        }
      } else {
        try {
          await runOptionActive(opt.id === 'tf_svc_bulk' ? { includeStore } : {}, opt);
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
    aiBtn.addEventListener('click', genAdviceActive);
  }

  function closeOptModal() {
    if (optModal) { optModal.close(); optModal = null; }
    activeOption = null;
  }

  // ==================== 执行 & AI ====================
  let OPTIONS = [];
  function getOptionTitle(id) {
    const o = OPTIONS.find(x => x.id === id);
    return o ? o.title : id;
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
        const bk = await window.api.optimizer.backupReg(opt.id, opt.steps || []);
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
      const runParams = Object.assign({}, params || {});
      if (!runParams.restore && HAZARD_OPTION_IDS.has(opt.id)) runParams.confirmedHighRisk = true;
      const resp = await window.api.optimizer.run(opt.id, runParams);
      if (resp && resp.success) {
        finishProgressToast(true, resp.message);
        window.app?.log('info', `优化电脑完成: ${optName}`);
        // v2.6.0（P0-2）：执行后回读校验不符（主进程已逐键比对）——明确告知而非静默成功
        if (resp.verify === 'partial') {
          window.app?.log('warn', `回读校验不符（可能被组策略/安全软件覆盖）: ${optName}`);
          window.app?.toast('warning', `「${optName}」已执行但读回校验不符，可能被组策略或安全软件覆盖`, 6000);
        }
        // 安全托底：执行成功后立即标记为已优化（灰态）
        if (params && params.restore) {
          optimizedIds.delete(opt.id);
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
        const elevated = await window.app?.requestElevation?.('优化电脑部分选项需要管理员权限才能修改系统注册表与服务。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新执行本优化项');
        return false;
      }
      finishProgressToast(false, resp && resp.message);
      window.app?.log('warn', `优化电脑失败: ${optName}: ${resp && resp.message || ''}`);
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
      window.app?.log?.('warn', '还原点查询失败（已放行，不视为无还原点）: ' + ((resp && resp.message) || '未知原因'));
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
    const batch = OPTIONS.filter(o => selectedIds.has(o.id));
    if (!batch.length) {
      window.app?.toast('warning', '请先勾选要执行的优化项');
      return;
    }
    // 高危项统计
    const hazardList = batch.filter(o => HAZARD_OPTION_IDS.has(o.id));
    const highCount = batch.filter(o => o.risk === 'high').length;
    const preview = batch.slice(0, 12).map(o => '· ' + o.title).join('\n') +
      (batch.length > 12 ? `\n…等共 ${batch.length} 项` : '');
    // 含高风险项时整批走红色二次确认，警示文案由 dangerHint 结构化渲染
    const hasHazard = hazardList.length > 0;
    const ok = await window.app.confirm(
      '执行所选优化',
      `将依次执行已勾选的 ${batch.length} 项优化（其中高风险 ${highCount} 项）：\n\n${preview}\n\n是否确认执行？`,
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

    // 高危项逐个红色二次确认
    for (const opt of hazardList) {
      const go = await confirmHazard(opt);
      if (!go) return;
    }

    if (!(await ensureRestorePoint())) return;

    batchRunning = true;
    const btn = document.getElementById('btnOptimizerSelected');
    if (btn) { btn.disabled = true; btn.dataset.orig = btn.innerHTML; btn.innerHTML = '执行中…'; }
    let okCount = 0, failCount = 0;
    const failedNames = [];
    for (let i = 0; i < batch.length; i++) {
      const opt = batch[i];
      // 进度 Toast 由 runOptionActive 内部创建（此前这里先建一条、内部再建一条并销毁前者）
      progressToastSuffix = `${i + 1}/${batch.length}`;
      try {
        const succeeded = await runOptionActive({}, opt);
        if (succeeded) {
          okCount++;
        }
        else { failCount++; failedNames.push(opt.title); }
      } catch (e) {
        failCount++; failedNames.push(opt.title);
      }
    }
    progressToastSuffix = '';
    batchRunning = false;
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig; delete btn.dataset.orig; }
    clearSelection();
    renderGroups(OPTIONS); // 刷新已优化灰态
    window.app?.toast(
      okCount === batch.length ? 'success' : 'warning',
      `执行完成：成功 ${okCount} 项，失败 ${failCount} 项` +
      (failCount ? `（${failedNames.slice(0, 5).join('、')}${failedNames.length > 5 ? ' 等' : ''}）` : '')
    );
  }

  // ==================== 一键全选当前页并依次执行 ====================
  function getCurrentPageOptions() {
    if (activeCategory === '全部') return OPTIONS.slice();
    return OPTIONS.filter(o => displayGroup(o) === activeCategory);
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
    const batch = getCurrentPageOptions();
    if (!batch.length) {
      window.app?.toast('warning', '当前页面没有可执行的优化项');
      return;
    }
    // 全选高亮，提示即将执行的项
    setCardsSelected(true);
    const highCount = batch.filter(o => o.risk === 'high').length;
    const hazardList = batch.filter(o => HAZARD_OPTION_IDS.has(o.id));
    const preview = batch.slice(0, 12).map(o => '· ' + o.title).join('\n') +
      (batch.length > 12 ? `\n…等共 ${batch.length} 项` : '');
    // 含高风险项时整批走红色二次确认，警示文案由 dangerHint 结构化渲染
    const ok = await window.app.confirm(
      '批量执行优化',
      `将依次执行当前页全部 ${batch.length} 项优化（其中高风险 ${highCount} 项）：\n\n${preview}\n\n是否确认执行？`,
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

    // 高危项逐个红色二次确认（合规强化）
    for (const opt of hazardList) {
      const go = await confirmHazard(opt);
      if (!go) { setCardsSelected(false); return; }
    }

    // 批次含「禁用 70+ 非必要服务」时：单独弹窗询问是否连商店相关服务一并禁用（一次询问作用于整批）
    let batchIncludeStore = false;
    if (batch.some(o => o.id === 'tf_svc_bulk')) {
      batchIncludeStore = await confirmIncludeStoreServices();
    }

    // 执行前统一检查系统还原点（未创建/超 5 天弹警示；用户最终拒绝则中止）
    if (!(await ensureRestorePoint())) { setCardsSelected(false); return; }

    batchRunning = true;
    const btn = document.getElementById('btnOptimizerBatch');
    if (btn) { btn.disabled = true; btn.dataset.orig = btn.innerHTML; btn.innerHTML = '批量执行中…'; }
    let okCount = 0, failCount = 0;
    const failedNames = [];
    for (let i = 0; i < batch.length; i++) {
      const opt = batch[i];
      // 进度 Toast 由 runOptionActive 内部创建（同上，消除每项一次白建白毁）
      progressToastSuffix = `${i + 1}/${batch.length}`;
      try {
        const succeeded = await runOptionActive(opt.id === 'tf_svc_bulk' ? { includeStore: batchIncludeStore } : {}, opt);
        if (succeeded) {
          okCount++;
        }
        else { failCount++; failedNames.push(opt.title); }
      } catch (e) {
        failCount++; failedNames.push(opt.title);
      }
    }
    progressToastSuffix = '';
    batchRunning = false;
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig; delete btn.dataset.orig; }
    setCardsSelected(false);
    clearSelection();
    renderGroups(OPTIONS); // 刷新已优化灰态
    window.app?.toast(
      okCount === batch.length ? 'success' : 'warning',
      `批量执行完成：成功 ${okCount} 项，失败 ${failCount} 项` +
      (failCount ? `（${failedNames.slice(0, 5).join('、')}${failedNames.length > 5 ? ' 等' : ''}）` : '')
    );
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
      Promise.all([pDisk, window.api.optimizer.list()]).then(([dt, res]) => {
        diskType = dt;
        if (res && res.success && Array.isArray(res.data)) {
          OPTIONS = filterByDiskType(res.data);
          activeCategory = getSavedCategory();
          renderCatNav();
          setCategory(activeCategory);
          bindEvents();
          // 安全托底：异步批量检测注册表项是否已优化（不阻塞首屏，结果回来后增量灰化）
          startOptimizedCheck();
          // v2.6.0（P0-1）：启动扫描已应用记账 + 未完成还原横幅 + 退役迁移结果回报
          loadStateOverview();
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
    root.addEventListener('click', (e) => {
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
        const ids = OPTIONS.filter(o => displayGroup(o) === group && !optimizedIds.has(o.id)).map(o => o.id);
        ids.forEach(id => selectedIds.add(id));
        renderGroups(OPTIONS);
        window.app?.toast('info', `已全选「${group}」${ids.length} 项，可点击「执行所选优化」批量执行`);
        return;
      }
      // 「更多调优项」→ 打开外设优化独立窗口
      const moreBtn = e.target.closest('.opt-col-more');
      if (moreBtn) {
        if (window.api?.peripheralWindow?.openWindow) {
          window.api.peripheralWindow.openWindow();
        } else {
          window.app?.toast('info', '外设优化窗口需在 Trim 应用内打开');
        }
        return;
      }
      const row = e.target.closest('.opt-row');
      if (!row) return;
      const id = row.dataset.id;
      const o = OPTIONS.find(x => x.id === id);
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

    const batchBtn = document.getElementById('btnOptimizerBatch');
    if (batchBtn) {
      batchBtn.addEventListener('click', () => { if (!window.api?.optimizer) window.app?.toast('warning', '当前为预览模式，无法执行优化'); else runBatch(); });
    }
    const selectedBtn = document.getElementById('btnOptimizerSelected');
    if (selectedBtn) {
      selectedBtn.disabled = true;
      selectedBtn.addEventListener('click', () => { if (!window.api?.optimizer) window.app?.toast('warning', '当前为预览模式，无法执行优化'); else runSelected(); });
    }
    // 分类切换时保留勾选状态（跨分类勾选允许执行所选）
    updateSelectedButtonState();
  }

  window.optimizer = { init, setCategory };
})();
