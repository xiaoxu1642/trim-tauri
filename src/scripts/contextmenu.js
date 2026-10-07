// contextmenu.js - 右键菜单管理模块（列表条目 + 详情弹窗 + AI 简介）
// 交互模式：勾选=启用，取消=禁用（可逆，直接写注册表/文件属性）；
// 删除为行内「备份并删除」按钮，操作不可逆。
(function () {
  'use strict';

  let items = [];
  let currentFilter = 'all';
  let isScanning = false;
  let hasScanned = false;
  let iconMap = {};        // clsid -> dataUrl
  let detailItem = null;   // 当前详情弹窗展示的条目
  let ctxModalCtrl = null; // v3.2.0：详情弹窗工厂 ctrl（焦点陷阱/Esc 由工厂统一管理）
  let kanbanMasonry = null; // 瀑布流布局引擎（resize 防抖 + FLIP）

  // 分类定义（顺序固定）。批次 C 起补齐三个原本「有 tab 无数据源」的分类：
  // 新建菜单 / 打开方式 / Win+X —— 侧边栏一直挂着这三个入口却永远为空。
  // ==================== 按软件分组（2026-10-05 用户裁定，替代原「按位置分类」） ====================
  // 归属由后端算：`owner` 是软件名，`ownerSource` 是它的判据来源（见 native/contextmenu.rs
  // 的 owner_of）。**空 owner = 后端明确说"不知道"**，一律进未识别组，前端绝不自己猜一个。
  const OWNER_UNKNOWN = '未识别 / 需人工确认';
  // 判据来源 → 组头上的可见注记：推断得来的必须标出来，不装作权威结论（§9.3 话术纪律）
  const OWNER_SOURCE_NOTE = {
    dir: '按安装目录识别',
    registry: '按注册表厂商',
    'pe-desc': '按文件说明',
    'pe-company': '按文件厂商',
  };
  // 判据权威性排序（与后端 owner_of 的优先级逐字一致）：同一软件在 PE 的 ProductName、
  // FileDescription、注册表 Company 里写法各不一样，组头要显示「最像软件名」的那条。
  const OWNER_LABEL_RANK = { system: 0, 'pe-product': 1, 'pe-desc': 2, registry: 3, 'pe-company': 4, dir: 5 };
  const rankOfSource = (s) => (Object.prototype.hasOwnProperty.call(OWNER_LABEL_RANK, s) ? OWNER_LABEL_RANK[s] : 99);

  /**
   * 分组键：把软件名里的「版本位 / 位数 / 壳扩展后缀 / 公司后缀」去掉，只留产品主干。
   * 不做这一步，WinRAR 会占三列（`WinRAR`、`WinRAR 64-bit Shell Extension`、`win.rar GmbH`），
   * 用户看到的就不是「这个软件挂了几处」而是「我们算了几遍归属」。
   * 只在主干完全相等时合并，所以 `Microsoft Edge` 与 `Microsoft Visual Studio` 不会被并成一列。
   */
  const OWNER_TOKEN_NOISE = new Set(['shell', 'shells', 'extension', 'extensions', 'ext',
    'context', 'menu', 'addin', 'add-in', 'plugin', 'bit', 'x64', 'x86', 'amd64',
    'gmbh', 'mbh', 'ag', 'inc', 'llc', 'ltd', 'limited', 'corp', 'corporation', 'co', 'company',
    'technologies', 'technology', 'software', 'systems', 'solutions', 'group', 'interactive', 'bv', 'sa']);
  function ownerGroupKey(label) {
    return String(label).toLowerCase().split(/[\s()]+/)
      .map(t => t.replace(/[^a-z0-9+]/g, ''))
      .filter(t => t && !OWNER_TOKEN_NOISE.has(t) && !/^\d+(bit)?$/.test(t))
      .join(' ');
  }

  // 位置（原「分类」）现在的用途只剩两个：行上的标签，以及组内排序的固定顺序。
  // 顺序表保留是因为它同时是扫描范围的可读清单（13 场景 + 发送到/Win+X/新建菜单/打开方式）。
  const CATEGORY_ORDER = [
    '文件', 'EXE文件', 'LNK文件', '目录', '文件夹',
    '驱动器', '回收站', '目录背景', '桌面背景',
    '此电脑', '库', '发送到', '新建菜单', '打开方式', 'Win+X', 'UWP应用'
  ];
  const CATEGORY_RANK = new Map(CATEGORY_ORDER.map((c, i) => [c, i]));

  const CATEGORY_ICONS = {
    '文件': '\u{1F4C4}',
    'EXE文件': '\u2699\uFE0F',
    'LNK文件': '\u{1F517}',
    '目录': '\u{1F4C1}',
    '文件夹': '\u{1F4C2}',
    '驱动器': '\u{1F4BF}',
    '回收站': '\u{1F6AE}',
    '目录背景': '\u{1F4CD}',
    '桌面背景': '\u{1F5A5}\uFE0F',
    '此电脑': '\u{1F5A5}\uFE0F',
    '库': '\u{1F4D6}',
    '发送到': '\u{1F4E8}',
    '新建菜单': '\u2795',
    '打开方式': '\u21AA',
    'Win+X': '\u2328',
    'UWP应用': '\u{1F4F1}'
  };

  // ==================== 看板式多列布局（按软件分组） ====================
  // 每个软件一列（白色圆角卡片），条目竖排：复选框(启用/禁用) + 序号 + 名称 + 位置 + 状态标签；
  // 列头 = 软件名（带该软件的真实图标）+「N 项 · M 个位置」；列底 =「全选本软件」；
  // 默认一行两列（kanbanMasonry 的 maxCols），窗口不够宽时退成一列。

  // 阶段三：类型/状态徽章统一 design-system（ds-badge sm 紧凑变体）
  // 「什么来路」这一维（系统保护 / 第三方 / 系统原生）按软件成列后是**组级事实**：
  // 同一家的菜单项来路相同，逐行重复一遍既抢宽度又没信息量，所以列头说一次、行内省略
  // （用户 2026-10-05 看真机截图后指定：徽章放到软件名后面，形如「WPS Office（第三方）」）。
  // 组内来路不一致时例外 —— 那种组每行都得自己说清楚，否则就是拿组头掩盖差异。
  const RISK_META = {
    protected: { tone: 'bad', label: '系统保护' },
    third: { tone: 'warn', label: '第三方' },
    system: { tone: 'ok', label: '系统原生' },
  };
  function riskKeyOf(item) {
    if (item.risk === 'protected') return 'protected';
    return item.isThirdParty ? 'third' : 'system';
  }
  function riskBadgeHtml(item) {
    const m = RISK_META[riskKeyOf(item)];
    return window.ds.badgeHtml(m.tone, m.label, { small: true });
  }
  function typeBadgeHtml(item, opts) {
    const hideRisk = !!(opts && opts.hideRisk);
    const badges = [];
    if (item.enabled === false) {
      // 三种禁用机制要如实区分：屏蔽表（Explorer 不加载）/ 外部工具的改名约定 / Trim 自己的可逆禁用
      const label = item.blockedBy ? '已屏蔽' : (item.unknownConvention ? '已禁用·外部约定' : '已禁用');
      const title = item.blockedBy
        ? `由 Shell Extensions\\Blocked 屏蔽表（${item.blockedBy === 'machine' ? '机器级' : '当前用户'}）禁用，资源管理器不会加载该扩展`
        : (item.unknownConvention
          ? '由其他工具（如 Autoruns）以改名方式禁用，Trim 未改动它'
          : '已禁用（取消勾选即可重新启用）');
      // 审计 P2-15：这些徽章原来各带一条「ds 缺席」降级分支，而降级分支里调的 escapeHtml
      // 本身就是 `window.ds.esc` —— ds 真不在时它先抛 TypeError，"降级"形同虚设。
      // ds.js 是子窗/主窗的强制依赖（§2 M17，由 check-html-contract 判红兜着），
      // 所以直接走 ds，不留一条走不通的假退路。
      badges.push(window.ds.badgeHtml('neutral', label, { small: true, title }));
    }
    if (item.orphan) {
      const why = item.orphanReason || '对应组件已不存在（多为软件卸载遗留）';
      badges.push(window.ds.badgeHtml('warn', '残留', { small: true, title: why + '；可安全清理' }));
    }
    const risk = hideRisk ? '' : riskBadgeHtml(item);
    return risk + (badges.length ? (risk ? ' ' : '') + badges.join(' ') : '');
  }

  // 是否支持启停切换。批次 B 起 UWP/打包 COM 走 Shell Extensions\Blocked 屏蔽表实现可逆禁用，
  // 但没有 CLSID 就无法入表，仍然不可切换。
  function isToggleable(item) {
    if (item.risk === 'protected') return false;
    if (['packagedcom', 'uwp-contract'].includes(item.source)) return !!item.clsid;
    return true;
  }

  // 模拟数据（用于浏览器预览模式；enabled 模拟启停状态）
  const MOCK_ITEMS = [
    { name: 'WinRAR', clsid: '{B41DB860-8EE4-11D2-9906-E49FADC173CA}', company: 'win.rar GmbH', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '文件', source: 'shellex', enabled: true },
    { name: 'Notepad++', clsid: '{00F29236-0000-0000-0000-000000000000}', company: 'Don Ho', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '文件', source: 'shellex', enabled: true },
    { name: '7-Zip', clsid: '{23170F69-40C1-278A-1000-000100020000}', company: 'Igor Pavlov', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '文件', source: 'shellex', enabled: true },
    { name: 'CopyAsPathMenu', clsid: '{DABB4F40-9D11-11D1-AB0A-00C04FC2DC31}', company: 'Microsoft Corporation', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: false, isProtected: false, risk: 'low', category: '文件', source: 'shellex', enabled: true },
    { name: 'ModernSharing', clsid: '{E2BF9D40-9D11-11D1-AB0A-00C04FC2DC31}', company: 'Microsoft Corporation', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: false, isProtected: false, risk: 'low', category: '文件', source: 'shellex', enabled: true },
    { name: 'AVG Shell Extension', clsid: '{9F7D8B6E-2A4F-4B9E-A1C8-3D5E7F9B2A1C}', company: 'AVG Technologies', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '文件', source: 'shellex', enabled: false },
    { name: 'McAfee File Encryption', clsid: '{A1B2C3D4-E5F6-7A8B-9C0D-1E2F3A4B5C6D}', company: 'McAfee, Inc.', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '文件', source: 'shellex', enabled: true },
    { name: '金山文档右键', clsid: '{K7F8A9B0-1C2D-3E4F-5A6B-7C8D9E0F1A2B}', company: 'Kingsoft Office', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '文件', source: 'shellex', enabled: true },
    { name: '百度网盘上传', clsid: '{B8A9F0C1-2D3E-4F5A-6B7C-8D9E0F1A2B3C}', company: '百度在线网络技术（北京）有限公司', location: 'HKCR\\*\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '文件', source: 'shellex', enabled: true },
    { name: '以管理员身份运行', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\exefile\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: 'EXE文件', source: 'shell', enabled: true },
    { name: '兼容性疑难解答', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\exefile\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: 'EXE文件', source: 'shell', enabled: true },
    { name: '打开文件所在位置', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\lnkfile\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: 'LNK文件', source: 'shell', enabled: true },
    { name: 'FileExplorerClassic', clsid: '{B41DB860-8EE4-11D2-9906-E49FADC173CB}', company: 'Microsoft Corporation', location: 'HKCR\\Directory\\shellex\\ContextMenuHandlers', isThirdParty: false, isProtected: false, risk: 'low', category: '目录', source: 'shellex', enabled: true },
    { name: '在终端中打开', clsid: '{E8F4C2A3-7C9F-4D9B-9F2C-7B2E1A4F8E6D}', company: 'Microsoft Corporation', location: 'HKCR\\Directory\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: '目录', source: 'shell', enabled: true },
    { name: '通过Git提交', clsid: '{A3B2C1D4-E5F6-7890-ABCD-EF0123456789}', company: 'Git SCM', location: 'HKCR\\Directory\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '目录', source: 'shellex', enabled: true },
    { name: 'WorkFolders', clsid: '{E8F4C2A3-7C9F-4D9B-9F2C-7B2E1A4F8E6D}', company: 'Microsoft Corporation', location: 'HKCR\\Folder\\shellex\\ContextMenuHandlers', isThirdParty: false, isProtected: false, risk: 'low', category: '文件夹', source: 'shellex', enabled: true },
    { name: '格式化', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\Drive\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: '驱动器', source: 'shell', enabled: true },
    { name: '磁盘清理', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\Drive\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: '驱动器', source: 'shell', enabled: true },
    { name: '我的电脑', clsid: '{20D04FE0-3AEA-1069-A2D8-08002B30309D}', company: 'Microsoft Corporation', location: 'HKCR\\Recycle.Bin\\shell', isThirdParty: false, isProtected: true, risk: 'protected', category: '回收站', source: 'shell', enabled: true },
    { name: '清空回收站', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\Recycle.Bin\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: '回收站', source: 'shell', enabled: true },
    { name: 'NVIDIAPowerUser', clsid: '{B41DB860-8EE4-11D2-9906-E49FADC173CC}', company: 'NVIDIA Corporation', location: 'HKCR\\Directory\\Background\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '目录背景', source: 'shellex', enabled: true },
    { name: '新建', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\Directory\\Background\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: '目录背景', source: 'shell', enabled: true },
    { name: '个性化', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\DesktopBackground\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: '桌面背景', source: 'shell', enabled: true },
    { name: '显示设置', clsid: '', company: 'Microsoft Corporation', location: 'HKCR\\DesktopBackground\\shell', isThirdParty: false, isProtected: false, risk: 'low', category: '桌面背景', source: 'shell', enabled: true },
    { name: 'Intel 显卡属性', clsid: '{C5B8A5E0-2A4F-4B9E-A1C8-3D5E7F9B2A1D}', company: 'Intel Corporation', location: 'HKCR\\DesktopBackground\\shellex\\ContextMenuHandlers', isThirdParty: true, isProtected: false, risk: 'high', category: '桌面背景', source: 'shellex', enabled: true },
    { name: '桌面快捷方式', clsid: '', company: 'Microsoft Corporation', location: '%APPDATA%\\Microsoft\\Windows\\SendTo', isThirdParty: false, isProtected: false, risk: 'low', category: '发送到', source: 'filesystem', enabled: true },
    { name: '邮件收件人', clsid: '', company: 'Microsoft Corporation', location: '%APPDATA%\\Microsoft\\Windows\\SendTo', isThirdParty: false, isProtected: false, risk: 'low', category: '发送到', source: 'filesystem', enabled: true },
    { name: '蓝牙设备', clsid: '', company: 'Microsoft Corporation', location: '%APPDATA%\\Microsoft\\Windows\\SendTo', isThirdParty: false, isProtected: false, risk: 'low', category: '发送到', source: 'filesystem', enabled: true },
    { name: '百度网盘', clsid: '', company: '百度在线网络技术', location: '%APPDATA%\\Microsoft\\Windows\\SendTo', isThirdParty: true, isProtected: false, risk: 'high', category: '发送到', source: 'filesystem', enabled: true },
    { name: 'Microsoft Edge (ShellExt)', clsid: '{C5B8A5E0-2A4F-4B9E-A1C8-3D5E7F9B2A2E}', company: 'Microsoft Corporation', location: 'HKCU\\Software\\Classes\\PackagedCom', isThirdParty: false, isProtected: false, risk: 'low', category: 'UWP应用', source: 'packagedcom', enabled: true },
    { name: 'Snip & Sketch', clsid: '{D8A9F0C1-2D3E-4F5A-6B7C-8D9E0F1A2B4D}', company: 'Microsoft Corporation', location: 'HKCU\\Software\\Classes\\PackagedCom', isThirdParty: false, isProtected: false, risk: 'low', category: 'UWP应用', source: 'packagedcom', enabled: true }
  ];

  // 获取按分类分组的项（叠加侧边栏分类筛选 + 顶部筛选标签）
  /**
   * 按软件分组（替代原先的「按位置分类」）。
   *
   * 排序权重是判据：这页的主用途是「看哪个软件挂了一堆菜单、能不能关掉」，所以
   * ① 第三方软件在最前，② Windows 系统组件其次（量大但基本不可动，排前面只会挤掉正主），
   * ③ 未识别组永远垫后（它是"我们也没查出来"的诚实兜底，不该出现在第一屏）。
   * 同权重内按项数降序 —— 挂得越多的软件越该先看。
   */
  function groupOwnerBy(list) {
    const map = new Map();
    for (const it of list) {
      const label = String(it.owner || '').trim() || OWNER_UNKNOWN;
      const key = label === OWNER_UNKNOWN ? OWNER_UNKNOWN : (ownerGroupKey(label) || label);
      if (!map.has(key)) map.set(key, { label, source: it.ownerSource || '', items: [] });
      const g = map.get(key);
      if (label !== OWNER_UNKNOWN && rankOfSource(g.source) > rankOfSource(it.ownerSource)) {
        g.label = label;
        g.source = it.ownerSource;
      }
      g.items.push(it);
    }
    // 排序看的是**判据来源**而不是标签文本：后端哪天改了这个显示名，前端不会静默失配
    const rank = (g) => (g.label === OWNER_UNKNOWN ? 2 : (g.source === 'system' ? 1 : 0));
    for (const g of map.values()) {
      // 组内按位置固定顺序排，同一位置的相邻 —— 「这个软件挂在哪些地方」一眼能数完
      g.items.sort((a, b) => (CATEGORY_RANK.has(a.category) ? CATEGORY_RANK.get(a.category) : 99)
        - (CATEGORY_RANK.has(b.category) ? CATEGORY_RANK.get(b.category) : 99));
      // 组内来路集合：只有一个值时由列头代答，行内就不再重复那枚徽章
      g.riskKeys = [...new Set(g.items.map(riskKeyOf))];
    }
    return [...map.values()].sort((a, b) => rank(a) - rank(b) || b.items.length - a.items.length);
  }

  // 界面分组与扫描完成的提示语走同一个 groupOwnerBy，不许有两套口径（AGENTS §5.16）
  function getGroupedOwners() {
    const filtered = items.filter(it => {
      if (currentFilter === 'all') return true;
      if (currentFilter === 'high') return it.risk === 'high' || it.risk === 'protected';
      if (currentFilter === 'low') return it.risk === 'low';
      if (currentFilter === 'disabled') return it.enabled === false;
      return true;
    });
    return groupOwnerBy(filtered);
  }

  // 获取某个分类下所有项的唯一标识
  function getItemKey(item) {
    // CLSID 可能在多个分类中复用，必须把分类和注册表路径纳入唯一键
    return [item.category || '', item.regPath || item.location || '', item.name || '', item.clsid || ''].join('|');
  }

  function escapeHtml(value) { return window.ds.esc(value); }

  // 默认占位图标（无程序图标时使用）。带 data-icon-fallback 标记，
  // 由 icon-fallback 共享兜底升级为 Trim.ico（B2：全场景统一兜底）；
  // Trim.ico 也提取失败时保留本问号占位。
  function placeholderIconHtml(size) {
    const s = size || 28;
    return `<span class="ctx-item-icon-placeholder" data-icon-fallback data-icon-size="${s}"><svg viewBox="0 0 24 24" width="${s}" height="${s}" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/></svg></span>`;
  }

  // 条目程序图标（有则展示提取的 DLL 图标，无则占位）
  function itemIconHtml(item, size) {
    if (item.clsid && iconMap[item.clsid]) {
      // 审查 v2-F14：同源的另一处（pathbinding.js groupIconHtml）写了 `escapeAttr` 而这里没写。
      // 该值不可注入（唯一产出口是「固定前缀 + 标准 base64」，字符集不含引号），
      // 但两处写法分裂会在下一次改动时踩雷 —— 统一走 `ds.escAttr` 这一唯一真源。
      return `<img class="ctx-item-icon" src="${window.ds.escAttr(iconMap[item.clsid])}" alt="" width="${size || 28}" height="${size || 28}" />`;
    }
    return placeholderIconHtml(size);
  }

  function renderList() {
    const container = document.getElementById('contextMenuList');
    if (!container) return;

    if (items.length === 0 && !hasScanned) {
      container.innerHTML = renderEmptyState('点击"扫描右键菜单"开始检测');
      return;
    }

    const groups = getGroupedOwners();
    if (!groups.length) {
      const msg = currentFilter === 'disabled' ? '暂无已禁用的项' : '没有匹配的项';
      container.innerHTML = renderEmptyState(msg);
      updateUI();
      return;
    }

    // 页头汇总：总条目数 + 软件数（原来是「N 个分类」）
    const totalShown = groups.reduce((s, g) => s + g.items.length, 0);
    const summary = document.getElementById('contextSummary');
    if (summary) summary.textContent = `共 ${totalShown} 项 · ${groups.length} 个软件`;

    // 看板：一列 = 一个软件。原来「空分类也占一列」是为了让扫描范围可见，
    // 按软件分组后空组根本不存在，扫描范围改由页头与详情弹窗交代。
    container.innerHTML = `<div class="ctx-kanban">` +
      groups.map(g => renderOwnerColumn(g)).join('') +
      `</div>`;

    // 绑定看板行：点击复选框切换启用/禁用，点击其余区域打开详情弹窗
    //（文字选中时跳过以支持复制；删除入口在详情弹窗内）
    container.querySelectorAll('.ctx-kanban-row').forEach(el => {
      el.addEventListener('click', e => {
        const key = el.dataset.itemKey;
        const item = items.find(i => getItemKey(i) === key);
        if (!item) return;
        if (e.target.closest('.checkbox')) {
          toggleItemEnabled(item);
          return;
        }
        if (window.getSelection && window.getSelection().toString()) return;
        openDetail(item);
      });
    });

    // 列底「全选本软件」：批量启用/禁用该软件全部可操作项
    container.querySelectorAll('[data-owner-selectall]').forEach(btn => {
      btn.addEventListener('click', () => {
        const g = groups.find(x => x.label === btn.dataset.ownerSelectall);
        if (g) toggleOwnerItems(g.label, g.items);
      });
    });

    // 瀑布流布局：重新渲染后立即放置；窗口 resize 由 attach 内部防抖 + FLIP 动画重排
    // 注意：布局容器是每次重渲染重建的 .ctx-kanban，须用 getter 动态获取
    // maxCols:2 —— 用户裁定「默认一行两列，最大限度展示信息」：软件组要放得下
    // 「挂在哪些位置」这一列信息，列数一多就被挤回原来的窄条样子。
    if (!kanbanMasonry && window.kanbanMasonry) {
      kanbanMasonry = window.kanbanMasonry.attach(
        () => container.querySelector('.ctx-kanban'), '.ctx-col', { gap: 14, minCard: 380, maxCols: 2 }
      );
    }
    if (kanbanMasonry) kanbanMasonry.relayout(false);

    updateUI();
  }

  /**
   * 看板列：列头（软件名 + 来路徽章 + 真实程序图标 + 「N 项 · M 个位置」+ 判据注记）
   * + 条目竖排（按位置排序）+ 列底「全选本软件」。
   *
   * 超过 50 项的组自动拆成两栏（用户 2026-10-05 指定）：本机「Windows 系统组件」104 项
   * 独占一栏时，整页高度被它一根柱子拉到几百屏，其它软件全被挤到它下面。拆成两栏后
   * 两栏各约一半，瀑布流正好把它们并排放进同一行。
   * 序号跨栏连续（1..N），所以「第 37 项」在两栏里指的是同一个东西；
   * 「全选本软件」两栏都给，且作用域都是**整组**，不是本栏那半 —— 否则点一栏只改半组。
   */
  const OWNER_SPLIT_AT = 50;
  function renderOwnerColumn(g) {
    const total = g.items.length;
    const uniform = g.riskKeys.length === 1;
    const headRisk = g.riskKeys.map(k => window.ds.badgeHtml(RISK_META[k].tone, RISK_META[k].label, { small: true })).join(' ');
    const icon = ownerIconHtml(g);
    const note = OWNER_SOURCE_NOTE[g.source];
    const parts = total > OWNER_SPLIT_AT
      ? [g.items.slice(0, Math.ceil(total / 2)), g.items.slice(Math.ceil(total / 2))]
      : [g.items];
    let offset = 0;
    return parts.map((part, pi) => {
      const start = offset;
      offset += part.length;
      const disabledCount = part.filter(it => it.enabled === false).length;
      const whereCount = new Set(part.map(it => it.category || '其他')).size;
      const bits = [`${part.length} 项`, `${whereCount} 个位置`];
      if (disabledCount > 0) bits.push(`${disabledCount} 已禁用`);
      if (parts.length > 1) bits.push(`共 ${total} 项 · 第 ${pi + 1}/${parts.length} 栏`);
      return `
      <div class="ctx-col" data-owner="${escapeHtml(g.label)}">
        <div class="ctx-col-head">
          <span class="ctx-col-title">${icon}${escapeHtml(g.label)}${headRisk ? ` ${headRisk}` : ''}</span>
          <span class="ctx-col-count">${escapeHtml(bits.join(' · '))}${note ? ` · ${escapeHtml(note)}` : ''}</span>
        </div>
        <div class="ctx-col-body">${part.map((item, i) => renderKanbanRow(item, start + i + 1, { hideRisk: uniform })).join('')}</div>
        <div class="ctx-col-foot">
          <button type="button" class="ctx-col-selectall" data-owner-selectall="${escapeHtml(g.label)}" data-tip="批量启用/禁用该软件的全部 ${total} 个菜单项（切换可逆）">全选本软件</button>
        </div>
      </div>`;
    }).join('');
  }

  /**
   * 组头图标：用该组第一个「提取到真实图标」的条目（多数壳扩展都能提到），
   * 这样软件名旁边就是用户在那个菜单里眼熟的图标，比通用占位更符合「一目了然」。
   * 一个都没有才退占位。
   */
  function ownerIconHtml(g) {
    const hit = g.items.find(it => it.clsid && iconMap[it.clsid]);
    if (hit) {
      return `<img class="ctx-col-icon" src="${window.ds.escAttr(iconMap[hit.clsid])}" alt="" width="20" height="20" />`;
    }
    return `<span class="ctx-col-icon">${placeholderIconHtml(20)}</span>`;
  }

  // 看板条目行：复选框 + 序号 + 名称 + 位置标签 + 状态标签（同一行内），详情图标钉在最右。
  // 两个标签都紧跟名称（用户 2026-10-05 裁定）：原来位置在名称下一行、状态在最右侧，
  // 一行只放得下六七个字却要占两行高，整页要多滑一倍；名称后面连着读也才是「什么东西·在哪·什么状态」。
  function renderKanbanRow(item, index, opts) {
    const key = getItemKey(item);
    const enabled = item.enabled !== false;
    const toggleable = isToggleable(item);
    return `
      <div class="ctx-kanban-row ${item.risk === 'protected' ? 'protected' : ''} ${enabled ? '' : 'disabled-row'}" data-item-key="${escapeHtml(key)}" data-tip="单击查看详情">
        <div class="checkbox ${enabled ? 'checked' : ''} ${toggleable ? '' : 'disabled'}" data-tip="${enabled ? '取消勾选禁用此项' : '勾选启用此项'}"></div>
        <span class="ctx-row-index">${index}</span>
        <span class="ctx-row-main">
          <span class="ctx-row-name">${escapeHtml(item.name)}</span>
          <span class="ctx-row-where">${escapeHtml(item.category || '其他')}</span>
          <span class="ctx-row-badges">${typeBadgeHtml(item, opts)}</span>
        </span>
        <span class="ctx-row-side"><span class="ctx-row-detail" data-tip="查看详情">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
        </span></span>
      </div>
    `;
  }

  // ==================== 详情弹窗 ====================
  // CM-9（2026-09-19）：HKCR 只是合并视图，条目真正住在哪个 hive 必须可见——
  // 备份/恢复/删除都按真实 hive 走，展示层再给一个 HKCR 路径会让人误判。
  function nativeRowHtml(item) {
    const native = item.nativeRegPath || '';
    const display = item.regPath || item.location || '';
    if (!native || native.toLowerCase() === display.toLowerCase()) return '';
    return `<div class="ctx-detail-row"><span class="ctx-detail-label">实际所在分支</span><span class="ctx-detail-value mono">${escapeHtml(native)}</span></div>`;
  }

  /**
   * 详情里的「软件归属」行：分组是它算出来的，所以判据必须在这看得见。
   * 未识别的条目也要出这一行 —— 空着比"看起来没有这个概念"更诚实。
   */
  function ownerRowHtml(item) {
    const owner = String(item.owner || '').trim() || OWNER_UNKNOWN;
    const note = OWNER_SOURCE_NOTE[item.ownerSource];
    const value = note ? `${owner}（${note}）` : owner;
    const tip = item.ownerSource === 'system' ? '文件在 Windows 目录下且厂商指向微软，按系统组件归组'
      : (item.ownerSource ? '' : '没有可执行文件线索（命令为空或只写了一个 verb），因此不猜软件名');
    return `<div class="ctx-detail-row"${tip ? ` data-tip="${escapeHtml(tip)}"` : ''}><span class="ctx-detail-label">软件归属</span><span class="ctx-detail-value">${escapeHtml(value)}</span></div>`;
  }

  // CM-13 / 批次 B、C：详情里常驻「为什么是这个状态」——风险提示、失效原因、屏蔽来源、外部约定。
  // 用户不必猜，也不必等点了勾选才被弹窗打断。
  function riskRowHtml(item) {
    const row = (label, value) => `<div class="ctx-detail-row"><span class="ctx-detail-label">${escapeHtml(label)}</span><span class="ctx-detail-value">${escapeHtml(value)}</span></div>`;
    const rows = [];
    if (item.confirmRequired) {
      rows.push(row('风险提示', item.confirmReason || '该项承载资源管理器的默认「打开/浏览」行为，禁用或删除需谨慎'));
    }
    if (item.orphan) {
      rows.push(row('失效残留', item.orphanReason || '对应组件已不存在（多为软件卸载遗留），可安全清理'));
    }
    if (item.blockedBy) {
      rows.push(row('屏蔽来源', `Shell Extensions\\Blocked 屏蔽表（${item.blockedBy === 'machine' ? '机器级 HKLM，解除需管理员' : '当前用户 HKCU'}）`));
    }
    if (item.unknownConvention) {
      rows.push(row('禁用方式', '由其他工具（如 Autoruns）以改名方式禁用，Trim 未改动它'));
    }
    return rows.join('');
  }

  // v3.2.0 弹窗统一批次：骨架改由 modal.js 工厂生成（ctx-detail-* 保留为内容样式），
  // Esc/遮罩关闭、焦点陷阱、打开关闭日志均由工厂统一接管（ctrl 声明见文件顶部）
  function openDetail(item) {
    closeDetail();
    detailItem = item;

    const badge = typeBadgeHtml(item);
    const regPath = item.regPath || item.location || '';
    const regJumpable = /^HK(LM|CR|CU|U|CC|PD)/i.test(regPath);

    ctxModalCtrl = window.modal.create({
      id: 'ctxDetailBackdrop',
      iconSvg: `<span class="ctx-detail-icon-wrap" data-role="iconWrap">${itemIconHtml(item, 40)}</span>`,
      metaHtml: `${badge}<span class="ctx-detail-cat">${CATEGORY_ICONS[item.category] || ''} ${escapeHtml(item.category || '其他')}</span>`,
      title: item.name,
      bodyClass: 'ctx-detail-body',
      bodyHtml: `
          <div class="ctx-detail-grid">
            <div class="ctx-detail-row"><span class="ctx-detail-label">注册表路径</span><span class="ctx-detail-value mono ${regJumpable ? 'ctx-reg-jump' : ''}" ${regJumpable ? 'data-role="regJump" data-tip="点击在注册表编辑器中定位（需要时会自动请求管理员权限）"' : ''}>${escapeHtml(regPath || '--')}</span></div>
            ${nativeRowHtml(item)}
            ${riskRowHtml(item)}
             <div class="ctx-detail-row"><span class="ctx-detail-label">所属公司</span><span class="ctx-detail-value">${escapeHtml(item.company || '--')}</span></div>
             ${ownerRowHtml(item)}
             ${item.filePath ? `<div class="ctx-detail-row"><span class="ctx-detail-label">组件路径</span><span class="ctx-detail-value mono">${escapeHtml(item.filePath)}</span></div>` : ''}
             ${item.command ? `<div class="ctx-detail-row"><span class="ctx-detail-label">执行命令</span><span class="ctx-detail-value mono">${escapeHtml(item.command)}</span></div>` : ''}
             ${item.clsid ? `<div class="ctx-detail-row"><span class="ctx-detail-label">CLSID</span><span class="ctx-detail-value mono">${escapeHtml(item.clsid)}</span></div>` : ''}
            <div class="ctx-detail-row"><span class="ctx-detail-label">组件类型</span><span class="ctx-detail-value">${item.isThirdParty ? '第三方软件' : '系统原生组件'}</span></div>
            <div class="ctx-detail-row"><span class="ctx-detail-label">用途说明</span><span class="ctx-detail-value">${escapeHtml(componentUsage(item))}</span></div>
          </div>
          <div class="ctx-detail-desc">
            <div class="ctx-detail-desc-title">简介</div>
            <div data-role="introMount"></div>
          </div>
          <div class="ctx-detail-actions">
            <button class="ctx-detail-delete" data-role="deleteBtn" data-tip="备份到桌面后删除此项（不可逆）">备份并删除</button>
          </div>`
    });
    const backdrop = ctxModalCtrl.backdrop;

    // B2：详情弹窗无真实图标时，占位符升级为统一的 Trim.ico 兜底图标
    if (window.iconFallback?.applyFallbacks) {
      window.iconFallback.applyFallbacks(backdrop.querySelector('[data-role="iconWrap"]'));
    }

    // 简介面板：打开即展示本地内置简介；联网 AI 简介须再次点击「获取AI简介」才请求大模型
    if (window.intro?.mountIntroPanel) {
      window.intro.mountIntroPanel({
        mount: backdrop.querySelector('[data-role="introMount"]'),
        scope: 'contextmenu',
        name: item.name,
        company: item.company,
        item
      });
    }

    // 详情内删除：先关闭弹窗，再走统一的「备份并删除」确认流程
    backdrop.querySelector('[data-role="deleteBtn"]').addEventListener('click', () => {
      const target = item;
      closeDetail();
      removeItem(target);
    });

    // 注册表路径：点击打开 regedit 并定位（需要时自动提权）
    const regJump = backdrop.querySelector('[data-role="regJump"]');
    if (regJump) {
      regJump.addEventListener('click', async e => {
        // 文字被选中时不触发跳转（支持复制路径）
        if (window.getSelection && window.getSelection().toString()) return;
        const path = item.regPath || item.location || '';
        if (!path) return;
        if (!window.api?.contextmenu?.openInRegedit) {
          window.app?.toast('info', '当前环境不支持打开注册表编辑器');
          return;
        }
        regJump.classList.add('jumping');
        try {
          const resp = await window.api.contextmenu.openInRegedit(path);
          if (resp && resp.success) {
            window.app?.toast('success', resp.message || '已在注册表编辑器中定位');
          } else {
            window.app?.toast('error', (resp && resp.message) || '打开注册表编辑器失败');
          }
        } catch (err) {
          window.app?.toast('error', '打开注册表编辑器失败: ' + err.message);
        } finally {
          regJump.classList.remove('jumping');
        }
      });
    }
  }

  // 组件用途静态说明（系统原生 / 第三方）
  function componentUsage(item) {
    const cat = item.category || '';
    if (item.isThirdParty) {
      return `由 ${item.company || '第三方厂商'} 提供的右键菜单扩展，在「${cat}」上右键时显示其功能入口。`;
    }
    return `Windows 系统原生右键菜单项，属于「${cat}」分类的系统内置功能。`;
  }

  function closeDetail() {
    // v3.2.0：骨架由工厂创建，close 即销毁（焦点陷阱/Esc 监听由工厂归还与移除）
    if (ctxModalCtrl) { ctxModalCtrl.close(); ctxModalCtrl = null; }
    detailItem = null;
  }

  // 注：AI 简介的加载、缓存与重试统一由 intro.js 的简介面板处理（scope = contextmenu），
  // 此处不再在打开详情时自动发起联网请求。

  // ==================== 图标加载 ====================
  async function loadIcons() {
    if (!window.api?.contextmenu?.icons || !items.length) return;
    try {
      const resp = await window.api.contextmenu.icons(items);
      if (resp.success && resp.data && Object.keys(resp.data).length) {
        iconMap = { ...iconMap, ...resp.data };
        renderList();
      }
    } catch (e) { /* 图标加载失败使用占位图标 */ }
  }

  function renderEmptyState(msg) {
    return window.emptyState
      ? window.emptyState({ icon: 'box', title: msg, desc: hasScanned ? '可尝试切换筛选条件，或重新扫描一次' : '点击右上角「扫描右键菜单」开始检测' })
      : `<div class="empty-state">
      <svg viewBox="0 0 24 24" width="48" height="48" fill="currentColor" opacity="0.3">
        <path d="M4 8h16v2H4V8zm0 5h16v2H4v-2zm0 5h16v2H4v-2z"/>
      </svg>
      <p>${msg}</p>
    </div>`;
  }

  function updateUI() {
    // 组头的「N 项 · M 个位置 · K 已禁用」由 renderOwnerColumn 直接写（每次重渲染重建 DOM），
    // 这里只留页面上那个常驻的已禁用总数。
    const countEl = document.getElementById('contextSelectedCount');
    if (countEl) countEl.textContent = items.filter(it => it.enabled === false).length;
  }

  // ==================== 启停切换（勾选=启用，取消=禁用） ====================
  // 统一批量通道：按 regPath 回写实际生效结果（权限不足 / 路径失效的项保持原状）
  async function applyToggles(payloads) {
    if (!payloads.length) return;
    if (!window.api?.contextmenu?.toggle) {
      // 浏览器预览模式：直接翻转本地状态
      payloads.forEach(p => { p.item.enabled = p.enabled; });
      renderList();
      updateUI();
      return;
    }
    try {
      const resp = await window.api.contextmenu.toggle(payloads.map(p => ({
        // 审查 CM-15（2026-09-15）：主进程 validateSnapshotItems 强制要求请求体带 id，
        // 漏传会让整批切换被判「不是最近一次扫描结果」直接拒绝（100% 失效）。
        id: p.item.id,
        name: p.item.name,
        regPath: p.item.regPath || p.item.location || '',
        source: p.item.source,
        enabled: p.enabled
      })));
      // 复核 N2（提权半闭环，2026-09-16）：HKLM/HKCR 范围项未提权时服务端回传 needAdmin，
      // 此前只报「切换失败（可能需要管理员权限）」、无提权入口；现在弹提权确认
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('切换这些右键菜单项需要管理员权限（写入 HKLM/HKCR 注册表）。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新执行切换');
        renderList();
        updateUI();
        return;
      }
      const results = (resp.data && resp.data.results) || [];
      // 审计 P1-2：命令层判负时回的是 `{success:false, message}` 且没有 data。旧代码不看
      // success，results 为空 ⇒ 下面既不 changed 也不 failed ⇒ 弹绿色「XX 已禁用」，
      // 真正的拒绝原因被丢掉。先认 success。
      if (resp && resp.success === false) {
        window.app?.toast('error', resp.message || '切换未生效');
        renderList();
        updateUI();
        return;
      }
      // 审计 P1-3：结果按 **id** 对位。原来按 regPath 对位，而「新建菜单」的 N 条项
      // 共享同一个 regPath（只有 target 不同）⇒ 后写的覆盖前写的 ⇒ 失败项被当成成功。
      const byId = {};
      const byPath = {};
      for (const r of results) {
        if (!r) continue;
        if (r.id) byId[r.id] = r;
        else if (r.regPath) byPath[r.regPath] = r;
      }
      let changed = 0, failed = 0, lastErr = '';
      for (const p of payloads) {
        const key = p.item.regPath || p.item.location || '';
        const r = (p.item.id ? byId[p.item.id] : null) || byPath[key];
        if (r && r.status === 'ok') {
          // 重命名类切换（shellex '-' 前缀 / 禁用前缀还原）后更新条目路径，
          // 保证不重新扫描的情况下反向切换仍能定位到键
          if (r.newRegPath) p.item.regPath = r.newRegPath;
          // CM-9：真实 hive 路径同步更新，后续备份/删除/启停都以它为准
          if (r.newNativeRegPath) p.item.nativeRegPath = r.newNativeRegPath;
          p.item.enabled = p.enabled;
          changed++;
        } else {
          failed++;
          if (r && r.message) lastErr = r.message;
        }
      }
      if (failed > 0) {
        window.app?.toast('error', lastErr
          ? `${failed} 项切换失败：${lastErr}`
          : `${failed} 项切换失败（可能需要管理员权限）`);
      } else if (payloads.length === 1) {
        const p = payloads[0];
        window.app?.toast(p.enabled ? 'success' : 'info', `${p.item.name} ${p.enabled ? '已启用' : '已禁用'}`);
      } else {
        window.app?.toast('success', `已${payloads[0].enabled ? '启用' : '禁用'} ${changed} 项`);
      }
      // 批次 B：改动要重启资源管理器才在菜单里可见，累计到生效条（不每次打断用户）
      if (changed > 0) markPendingApply(changed);
    } catch (e) {
      window.app?.toast('error', '切换失败: ' + e.message);
    }
    renderList();
    updateUI();
  }

  function toggleItemEnabled(item) {
    if (!isToggleable(item)) {
      if (item.risk === 'protected') {
        window.app?.toast('info', '系统保护项不可操作');
      } else {
        window.app?.toast('info', '该类型暂不支持启停切换');
      }
      return;
    }
    toggleItemsWithGuard([{ item, enabled: item.enabled === false }]);
  }

  // CM-13（2026-09-19，批次 A）：open / explore 等基础打开动词与快捷方式 open 处理器，
  // 禁用后用户感知是「双击打不开了」，必须先过红色二次确认（对齐参考实现的 ProtectOpenItem）。
  // 判据来自扫描端 confirmRequired，渲染层不自己猜键名。
  async function toggleItemsWithGuard(payloads) {
    if (!payloads.length) return;
    const risky = payloads.filter(p => p.item && p.item.confirmRequired && p.enabled === false);
    if (risky.length && window.api?.contextmenu?.toggle) {
      const lines = risky.map(p => '· ' + p.item.name + '：' + (p.item.confirmReason || '基础打开动词，禁用后双击与默认打开行为可能改变')).join('\n');
      const ok = await window.app?.confirmDanger(
        '禁用基础打开项',
        `即将禁用 ${risky.length} 项：\n${lines}`,
        '确认禁用',
        '取消',
        '这类项承载资源管理器的默认「打开/浏览」行为，禁用后可能出现双击无反应，需重新启用才能恢复。'
      );
      if (!ok) return;
    }
    // 保护项只拦「禁用方向」：已经禁用的要恢复启用时无需吓阻
    await applyToggles(payloads);
  }

  async function toggleOwnerItems(owner, ownerItems) {
    const toggleableItems = ownerItems.filter(it => isToggleable(it));
    if (!toggleableItems.length) return;
    const target = !toggleableItems.every(it => it.enabled !== false);
    const affected = toggleableItems.filter(it => (it.enabled !== false) !== target);
    if (!affected.length) return;
    if (affected.length > 3) {
      const ok = await window.app?.confirm(
        '批量切换',
        `即将${target ? '启用' : '禁用'}「${owner}」的 ${affected.length} 个右键菜单项（切换为可逆操作）。\n\n是否继续？`,
        '确认切换'
      );
      if (!ok) return;
    }
    // CM-13：批量路径同样要过基础打开项的红色确认（否则「全选本软件」可一键禁掉 open 动词）
    toggleItemsWithGuard(affected.map(item => ({ item, enabled: target })));
  }

  // ==================== 行内删除（先备份后删除，不可逆） ====================
  // 审查v4-M3：右键项删除不可逆（注册表删除无回收站语义），按规范走红色二次确认，
  // dangerHint 明示备份目录是唯一恢复手段
  async function removeItem(item) {
    // CM-13：基础打开项删除时在 dangerHint 里点明额外后果
    const openHint = item.confirmRequired
      ? `\n注意：${item.confirmReason || '该项是基础打开动词'}。`
      : '';
    const ok = await window.app?.confirmDanger(
      '删除右键菜单项',
      `即将备份并删除「${item.name}」。\n备份文件将保存到桌面"右键菜单备份_时间戳"目录。\n\n是否继续？`,
      '确认删除',
      '取消',
      '该操作不可逆（注册表删除无回收站语义），桌面备份目录是唯一恢复手段。' + openHint
    );
    if (!ok) return;
    try {
      if (window.api?.contextmenu) {
        const backupResp = await window.api.contextmenu.backup([item]);
        if (!backupResp?.success) throw new Error(backupResp?.message || '备份失败，已停止删除');
        const resp = await window.api.contextmenu.remove([{
          // 审查 CM-15：remove 同样要求 id 才能通过快照校验（否则项未删却报错）
          id: item.id,
          name: item.name, regPath: item.regPath, risk: item.risk, source: item.source, clsid: item.clsid, category: item.category
        }]);
        // 复核 N2：提权半闭环收口（同 applyToggles）
        if (resp && resp.needAdmin) {
          const elevated = await window.app?.requestElevation?.('删除该菜单项需要管理员权限（写入 HKLM/HKCR 注册表）。');
          if (elevated) window.app?.toast('info', '已获得管理员权限，请重新执行删除');
          return;
        }
        if (!resp.success) throw new Error(resp.message);
        window.app?.toast('success', '已备份并删除所选菜单项');
        markPendingApply(1);
      } else {
        // 预览模式（审查v4-L8：全局横幅替代逐条 [模拟] 前缀）
        await new Promise(r => setTimeout(r, 800));
        window.app?.showPreviewModeBanner?.();
        window.app?.toast('success', `已备份到桌面，并删除「${item.name}」`);
      }
      items = items.filter(i => getItemKey(i) !== getItemKey(item));
      if (detailItem === item) closeDetail();
      renderList();
      updateUI();
    } catch (e) {
      window.app?.toast('error', '操作失败: ' + e.message);
    }
  }

  // v3.2.1：refresh=false 优先读持久缓存（首启扫描一次落盘，之后一直读文件，init 时自动加载）；
  // true 强制重新扫描并覆盖缓存。删除/启停后走 true 保证拿到最新状态。
  async function scan(refresh = false) {
    if (isScanning) return;
    isScanning = true;
    if (refresh) { items = []; iconMap = {}; hasScanned = false; }

    const container = document.getElementById('contextMenuList');
    if (container && !hasScanned) {
      container.innerHTML = `<div class="empty-state">
        <svg viewBox="0 0 24 24" width="48" height="48" fill="currentColor" opacity="0.5" class="spin">
          <path d="M12 4V2A10 10 0 0 0 2 12h2a8 8 0 0 1 8-8z"/>
        </svg>
        <p>正在扫描右键菜单扩展项...</p>
      </div>`;
    }

    try {
      if (window.api?.contextmenu) {
        const resp = await window.api.contextmenu.scan(refresh);
        if (!resp.success) throw new Error(resp.message);
        items = resp.data;
      } else {
        // 预览模式
        await new Promise(r => setTimeout(r, 1200));
        items = MOCK_ITEMS.map(m => ({
          ...m,
          regPath: m.location + '\\' + m.name,
          // 浏览器预览模式没有后端那条解析链，归属退到「注册表厂商」这一级；
          // 厂商也没有的就进未识别组（与真实链路同一行为，不为了预览好看而编）
          owner: m.company || '',
          ownerSource: m.company ? 'registry' : '',
        }));
      }
      hasScanned = true;
      renderList();
      updateUI();
      // 后台加载程序图标，加载完成后刷新列表
      loadIcons();

      // 提示语跟着分组轴走：用户现在看到的是「几个软件」，报「几个分类」会对不上界面
      const ownerCount = groupOwnerBy(items).length;
      window.app?.toast('success', `扫描完成，共发现 ${items.length} 项，属于 ${ownerCount} 个软件（含未识别组）`);
    } catch (e) {
      window.app?.toast('error', '扫描失败: ' + e.message);
      if (container) {
        container.innerHTML = `<div class="empty-state"><p>扫描失败: ${escapeHtml(e.message)}</p></div>`;
      }
    } finally {
      isScanning = false;
      updateUI();
    }
  }

  async function restore() {
    // 审查 v2-M11：同一条链路上「删除」已是红色确认（本文件 removeItem），「写回」却只是
    // 普通 confirm ⇒ 确认等级方向反了——恢复会整批导入 .reg 并覆盖文件，破坏性不低于删除。
    // 判据不来自这里：服务端已按 v2-K1 只导 manifest 登记且键路径合法的备份、并且要求提权。
    const ok = await window.app?.confirmDanger?.(
      '⚠️ 从备份恢复右键菜单',
      '将用桌面上最新的那个「右键菜单备份_*」目录整体覆盖当前右键菜单设置：\n'
      + '· 只导入该目录内、由本应用 manifest 登记过、且键路径落在注册表 Classes 范围内的备份文件；\n'
      + '· 「发送到」/Win+X 的文件项会被备份内容覆盖，你对这些项的手动改动会丢失；\n'
      + '· 此操作会写入注册表并可能影响机器级项，需要管理员权限。',
      '仍然恢复',
      '取消',
      '恢复是整批覆盖，不是逐项选择。如需保留现状请先另存一份当前设置。'
    );
    if (!ok) return;
    try {
      if (window.api?.contextmenu) {
        const resp = await window.api.contextmenu.restore();
        // v2-K1 给服务端补了提权闸门：未提权时回 needAdmin，走本页既有的提权握手
        if (resp && resp.needAdmin) {
          const elevated = await window.app?.requestElevation?.('恢复右键菜单备份需要管理员权限（可能写入 HKLM 注册表）。');
          if (elevated) window.app?.toast('info', '已获得管理员权限，请重新执行恢复');
          return;
        }
        if (!resp.success) throw new Error(resp.message);
        const d = resp.data || {};
        const n = Number(d.imported || 0) + Number(d.restored || 0);
        window.app?.toast('success', `已从 ${d.backupDir} 恢复 ${n} 项`);
        // CM-9：旧版本产出的备份头是 HKCR，导入会落到 HKLM，服务端一律拒收并回报 skipped。
        // 这种情况必须如实告诉用户，不能让他以为「恢复成功了」。原因由服务端逐条给出，
        // 这里不把某一种猜测写死成结论（拒收原因实际有五种，见 native 的 skipReasons）。
        if (Number(d.skipped || 0) > 0) {
          const reasons = Array.isArray(d.skipReasons) ? d.skipReasons.slice(0, 3).join('；') : '';
          window.app?.toast('warning', `有 ${d.skipped} 个备份被拒绝导入${reasons ? '：' + reasons : ''}`, 6000);
        }
        if (n > 0) markPendingApply(n);
      } else {
        await new Promise(r => setTimeout(r, 800));
        window.app?.showPreviewModeBanner?.();
        window.app?.toast('info', '已恢复最新备份（预览模式，无实际操作）');
      }
    } catch (e) {
      window.app?.toast('error', '恢复失败: ' + e.message);
    }
  }

  function setFilter(filter) {
    currentFilter = filter;
    document.querySelectorAll('#contextFilter .filter-tab').forEach(el => {
      el.classList.toggle('active', el.dataset.filter === filter);
    });
    renderList();
    updateUI();
  }

  // ==================== 批次 B：延迟批量生效（重启资源管理器） ====================
  // 右键菜单由 Explorer 在加载期解析，任何启停/删除/模式切换都要重启才看得到。
  // 学参考实现的做法：不每改一项就打断用户，累计改动，由用户一次性重启。
  let pendingApply = 0;

  function markPendingApply(count) {
    const n = Number(count) || 0;
    if (n <= 0) return;
    pendingApply += n;
    renderApplyBar();
  }

  function renderApplyBar() {
    const bar = document.getElementById('ctxApplyBar');
    const text = document.getElementById('ctxApplyText');
    if (!bar || !text) return;
    if (pendingApply <= 0) { bar.hidden = true; return; }
    text.textContent = `已有 ${pendingApply} 项改动写入注册表，重启资源管理器后才会在右键菜单里生效。`;
    bar.hidden = false;
  }

  async function restartExplorer() {
    // 审查 M-07 订正：原判「整处未包裹」不成立——下方 restartExplorer 调用本身已有
    // try/catch/finally。真正的缺口是这个函数被**直接当事件监听器**注册
    // （init(): btnCtxRestartExplorer.addEventListener('click', restartExplorer)），
    // 而 confirmDanger 那次 await 在 try 之外：它一旦 reject（模态被异常关闭等），
    // 就会变成无人接的 Promise rejection，调用方连 toast 都拿不到。
    try {
      if (!window.api?.contextmenu?.restartExplorer) {
        window.app?.toast('info', '当前环境不支持重启资源管理器');
        return;
      }
      // 重启会关掉用户已打开的文件夹窗口，按红线走红色确认，不静默执行
      const ok = await window.app?.confirmDanger(
        '重启资源管理器',
        '将结束并重新打开当前会话的资源管理器（explorer.exe）。\n桌面与任务栏会短暂消失后自动恢复，已打开的文件夹窗口会被关闭。',
        '确认重启',
        '取消',
        '只影响当前登录会话；其他用户与服务会话的资源管理器不受影响。'
      );
      if (!ok) return;
      const btn = document.getElementById('btnCtxRestartExplorer');
      if (btn) btn.disabled = true;
      try {
        const resp = await window.api.contextmenu.restartExplorer();
        if (resp && resp.success) {
          pendingApply = 0;
          renderApplyBar();
          window.app?.toast('success', (resp.data && resp.data.message) || '已重启资源管理器');
        } else {
          window.app?.toast('error', (resp && resp.message) || '重启资源管理器失败');
        }
      } catch (e) {
        window.app?.toast('error', '重启资源管理器失败: ' + e.message);
      } finally {
        if (btn) btn.disabled = false;
      }
    } catch (e) {
      window.app?.toast('error', '重启资源管理器失败: ' + ((e && e.message) || e));
    }
  }

  function init() {
    // 「扫描」按钮 = 强制真实扫描并覆盖缓存（v3.2.1 缓存政策）
    document.getElementById('btnScanContext')?.addEventListener('click', () => scan(true));
    document.getElementById('btnRestoreMenu')?.addEventListener('click', restore);
    // 批次 B：生效条
    document.getElementById('btnCtxRestartExplorer')?.addEventListener('click', restartExplorer);
    document.getElementById('btnCtxApplyDismiss')?.addEventListener('click', () => {
      pendingApply = 0;
      renderApplyBar();
      window.app?.toast('info', '改动已写入注册表，稍后可在资源管理器任务栏右键或重登后生效');
    });
    renderApplyBar();
    // v3.2.1：进入页面自动加载缓存（首次无缓存时自动扫描一次并落盘）
    scan(false);

    document.querySelectorAll('#contextFilter .filter-tab').forEach(el => {
      el.addEventListener('click', () => setFilter(el.dataset.filter));
    });
    // 原「侧边栏分类树」那一段（点击切分类 + 持久化 + 切换提示）随分类栏一起删除：
    // 分组轴改成软件后，位置已经是行上看得见的标签，不需要再靠切视图才能看到全貌。
  }

  window.contextmenu = { init, scan, removeItem, restore, MOCK_ITEMS, CATEGORY_ORDER, openDetail };
})();
