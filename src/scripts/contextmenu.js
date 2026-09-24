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
  const CATEGORY_ORDER = [
    '文件', 'EXE文件', 'LNK文件', '目录', '文件夹',
    '驱动器', '回收站', '目录背景', '桌面背景',
    '此电脑', '库', '发送到', '新建菜单', '打开方式', 'Win+X', 'UWP应用'
  ];

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

  // ==================== 侧边栏分类筛选（叠加生效，切换时保留勾选） ====================
  // 侧边栏分组选项 -> 条目匹配函数（「全部」为扁平汇总视图；
  // 标准分类直接匹配，特殊分类按注册表路径正则匹配）
  const SIDEBAR_CATEGORY_MATCH = {
    '全部': () => true,
    '文件': it => ['文件', 'EXE文件', 'LNK文件'].includes(it.category),
    '文件夹': it => it.category === '文件夹',
    '目录': it => it.category === '目录',
    '目录背景': it => it.category === '目录背景',
    '桌面背景': it => it.category === '桌面背景',
    '磁盘分区': it => it.category === '驱动器',
    '所有对象': it => /AllFilesystemObjects/i.test(it.regPath || it.location || ''),
    '此电脑': it => /\{20D04FE0-/i.test(it.regPath || it.location || ''),
    '回收站': it => it.category === '回收站' || /Recycle\.Bin/i.test(it.regPath || it.location || ''),
    '库': it => /Library/i.test(it.regPath || it.location || ''),
    '新建菜单': it => it.category === '新建菜单',
    '发送到': it => it.category === '发送到' || /SendTo/i.test(it.regPath || it.location || ''),
    '打开方式': it => it.category === '打开方式',
    'Win+X': it => it.category === 'Win+X'
  };
  let currentCategory = '文件';

  // ==================== 看板式多列布局 ====================
  // 每个分类一列（白色圆角卡片），条目竖排：复选框(启用/禁用) + 序号 + 名称(可换行不截断) + 类型/状态标签；
  // 列头 = 分类名 + 项数徽章；列底 = 「全选本类」；窗口不够宽时容器横向滚动。

  // 阶段三：类型/状态徽章统一 design-system（ds-badge sm 紧凑变体）
  function typeBadgeHtml(item) {
    const badges = [];
    if (item.enabled === false) {
      // 三种禁用机制要如实区分：屏蔽表（Explorer 不加载）/ 外部工具的改名约定 / Trim 自己的可逆禁用
      const label = item.blockedBy ? '已屏蔽' : (item.unknownConvention ? '已禁用·外部约定' : '已禁用');
      const title = item.blockedBy
        ? `由 Shell Extensions\\Blocked 屏蔽表（${item.blockedBy === 'machine' ? '机器级' : '当前用户'}）禁用，资源管理器不会加载该扩展`
        : (item.unknownConvention
          ? '由其他工具（如 Autoruns）以改名方式禁用，Trim 未改动它'
          : '已禁用（取消勾选即可重新启用）');
      badges.push(window.ds
        ? window.ds.badgeHtml('neutral', label, { small: true, title })
        : `<span class="badge off" data-tip="${escapeHtml(title)}">${escapeHtml(label)}</span>`);
    }
    if (item.orphan) {
      const why = item.orphanReason || '对应组件已不存在（多为软件卸载遗留）';
      badges.push(window.ds
        ? window.ds.badgeHtml('warn', '残留', { small: true, title: why + '；可安全清理' })
        : `<span class="badge third-party" data-tip="${escapeHtml(why)}">残留</span>`);
    }
    const risk = item.risk === 'protected'
      ? (window.ds ? window.ds.badgeHtml('bad', '系统保护', { small: true }) : '<span class="badge protected">系统保护</span>')
      : (item.isThirdParty
        ? (window.ds ? window.ds.badgeHtml('warn', '第三方', { small: true }) : '<span class="badge third-party">第三方</span>')
        : (window.ds ? window.ds.badgeHtml('ok', '系统原生', { small: true }) : '<span class="badge system">系统原生</span>'));
    return risk + (badges.length ? ' ' + badges.join(' ') : '');
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
  function getGroupedItems() {
    const grouped = {};
    for (const cat of CATEGORY_ORDER) {
      grouped[cat] = [];
    }
    const catMatcher = SIDEBAR_CATEGORY_MATCH[currentCategory] || SIDEBAR_CATEGORY_MATCH['全部'];
    const filtered = items.filter(it => {
      // 侧边栏分类筛选（叠加生效）
      if (catMatcher && !catMatcher(it)) return false;
      if (currentFilter === 'all') return true;
      if (currentFilter === 'high') return it.risk === 'high' || it.risk === 'protected';
      if (currentFilter === 'low') return it.risk === 'low';
      if (currentFilter === 'disabled') return it.enabled === false;
      return true;
    });
    for (const it of filtered) {
      const cat = it.category || '其他';
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(it);
    }
    return grouped;
  }

  // 获取某个分类下所有项的唯一标识
  function getItemKey(item) {
    // CLSID 可能在多个分类中复用，必须把分类和注册表路径纳入唯一键
    return [item.category || '', item.regPath || item.location || '', item.name || '', item.clsid || ''].join('|');
  }

  function escapeHtml(value) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(value ?? '').replace(/[&<>"']/g, ch => map[ch]);
  }

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
      return `<img class="ctx-item-icon" src="${iconMap[item.clsid]}" alt="" width="${size || 28}" height="${size || 28}" />`;
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

    const grouped = getGroupedItems();
    // 扫描完成后固定展示全部分类，即使某一类暂时没有注册项，也能明确看到扫描范围。
    const activeCategories = (currentFilter === 'all' || currentFilter === 'disabled')
      ? CATEGORY_ORDER
      : CATEGORY_ORDER.filter(cat => grouped[cat] && grouped[cat].length > 0);

    const nonEmptyCategories = activeCategories.filter(cat => (grouped[cat] || []).length > 0);
    if (nonEmptyCategories.length === 0) {
      const msg = currentFilter === 'disabled'
        ? '暂无已禁用的项'
        : (hasScanned ? `「${currentCategory}」分类下暂无匹配项` : '没有匹配的项');
      container.innerHTML = renderEmptyState(msg);
      return;
    }

    // 页头汇总：总条目数 + 分类总数
    const totalShown = nonEmptyCategories.reduce((s, cat) => s + (grouped[cat] || []).length, 0);
    const summary = document.getElementById('contextSummary');
    if (summary) summary.textContent = `共 ${totalShown} 项 · ${nonEmptyCategories.length} 个分类`;

    // 所有看板按项数从少到多升序排列（稳定排序，项数相同保持原相对顺序）
    const sortedCategories = [...nonEmptyCategories].sort(
      (a, b) => (grouped[a] || []).length - (grouped[b] || []).length
    );

    // 看板：瀑布流（Masonry）排布，按升序依次放入最矮列底部
    container.innerHTML = `<div class="ctx-kanban">` +
      sortedCategories.map(cat => renderCategoryColumn(cat, grouped[cat])).join('') +
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

    // 列底「全选本类」：批量启用/禁用该分类全部可操作项
    container.querySelectorAll('[data-col-selectall]').forEach(btn => {
      btn.addEventListener('click', () => {
        const cat = btn.dataset.colSelectall;
        toggleCategoryItems(cat, grouped[cat] || []);
      });
    });

    // 瀑布流布局：重新渲染后立即放置；窗口 resize 由 attach 内部防抖 + FLIP 动画重排
    // 注意：布局容器是每次重渲染重建的 .ctx-kanban，须用 getter 动态获取
    if (!kanbanMasonry && window.kanbanMasonry) {
      kanbanMasonry = window.kanbanMasonry.attach(
        () => container.querySelector('.ctx-kanban'), '.ctx-col', { gap: 14, minCard: 246 }
      );
    }
    if (kanbanMasonry) kanbanMasonry.relayout(false);

    updateUI();
  }

  // 看板列：列头（分类名 + 项数徽章）+ 条目竖排 + 列底「全选本类」
  function renderCategoryColumn(cat, catItems) {
    const icon = CATEGORY_ICONS[cat] || '\u{1F4C4}';
    const disabledCount = catItems.filter(it => it.enabled === false).length;
    const metaText = disabledCount > 0 ? `${catItems.length} 项 · ${disabledCount} 已禁用` : `${catItems.length} 项`;
    const rows = catItems.map((item, i) => renderKanbanRow(item, i + 1)).join('');
    return `
      <div class="ctx-col" data-category="${escapeHtml(cat)}">
        <div class="ctx-col-head">
          <span class="ctx-col-title"><span class="ctx-col-icon">${icon}</span>${escapeHtml(cat)}</span>
          <span class="ctx-col-count" data-cat-meta="${escapeHtml(cat)}">${escapeHtml(metaText)}</span>
        </div>
        <div class="ctx-col-body">${rows}</div>
        <div class="ctx-col-foot">
          <button type="button" class="ctx-col-selectall" data-col-selectall="${escapeHtml(cat)}" data-tip="批量启用/禁用该分类全部可操作项">全选本类</button>
        </div>
      </div>
    `;
  }

  // 看板条目行：复选框(启用/禁用) + 序号 + 名称(可换行) + 类型/状态标签 + 详情图标（厂商信息只在详情弹窗展示）
  function renderKanbanRow(item, index) {
    const key = getItemKey(item);
    const enabled = item.enabled !== false;
    const toggleable = isToggleable(item);
    return `
      <div class="ctx-kanban-row ${item.risk === 'protected' ? 'protected' : ''} ${enabled ? '' : 'disabled-row'}" data-item-key="${escapeHtml(key)}" data-tip="单击查看详情">
        <div class="checkbox ${enabled ? 'checked' : ''} ${toggleable ? '' : 'disabled'}" data-tip="${enabled ? '取消勾选禁用此项' : '勾选启用此项'}"></div>
        <span class="ctx-row-index">${index}</span>
        <span class="ctx-row-main">
          <span class="ctx-row-name">${escapeHtml(item.name)}</span>
        </span>
        <span class="ctx-row-side">${typeBadgeHtml(item)}<span class="ctx-row-detail" data-tip="查看详情">
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
      ? window.emptyState({ icon: 'box', title: msg, desc: hasScanned ? '可尝试切换分类或筛选条件，或重新扫描' : '点击右上角「扫描右键菜单」开始检测' })
      : `<div class="empty-state">
      <svg viewBox="0 0 24 24" width="48" height="48" fill="currentColor" opacity="0.3">
        <path d="M4 8h16v2H4V8zm0 5h16v2H4v-2zm0 5h16v2H4v-2z"/>
      </svg>
      <p>${msg}</p>
    </div>`;
  }

  function updateUI() {
    // 更新分类元信息（含禁用计数）
    const grouped = getGroupedItems();
    for (const cat of CATEGORY_ORDER) {
      const catItems = grouped[cat] || [];
      if (catItems.length === 0) continue;
      const metaEl = document.querySelector(`[data-cat-meta="${cat}"]`);
      if (!metaEl) continue;
      const disabledCount = catItems.filter(it => it.enabled === false).length;
      metaEl.textContent = disabledCount > 0 ? `${catItems.length} 项 · ${disabledCount} 已禁用` : `${catItems.length} 项`;
    }

    // 总览：已禁用计数
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
      const byPath = {};
      for (const r of results) byPath[r.regPath] = r;
      let changed = 0, failed = 0;
      for (const p of payloads) {
        const key = p.item.regPath || p.item.location || '';
        if (results.length === 0) continue;
        const r = byPath[key];
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
        }
      }
      if (failed > 0) {
        window.app?.toast('error', `${failed} 项切换失败（可能需要管理员权限）`);
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

  async function toggleCategoryItems(cat, catItems) {
    const toggleableItems = catItems.filter(it => isToggleable(it));
    if (!toggleableItems.length) return;
    const target = !toggleableItems.every(it => it.enabled !== false);
    const affected = toggleableItems.filter(it => (it.enabled !== false) !== target);
    if (!affected.length) return;
    if (affected.length > 3) {
      const ok = await window.app?.confirm(
        '批量切换',
        `即将${target ? '启用' : '禁用'}「${cat}」分类下 ${affected.length} 项（切换为可逆操作）。\n\n是否继续？`,
        '确认切换'
      );
      if (!ok) return;
    }
    // CM-13：批量路径同样要过基础打开项的红色确认（否则「全选本类」可一键禁掉 open 动词）
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
        items = MOCK_ITEMS.map(m => ({ ...m, regPath: m.location + '\\' + m.name }));
      }
      hasScanned = true;
      renderList();
      updateUI();
      // 后台加载程序图标，加载完成后刷新列表
      loadIcons();

      const catCount = CATEGORY_ORDER.filter(c => items.some(i => (i.category || '其他') === c)).length;
      window.app?.toast('success', `扫描完成，共发现 ${items.length} 项，分布于 ${catCount} 个分类`);
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
    const ok = await window.app?.confirm(
      '从备份恢复',
      '将使用桌面上的最新备份目录（右键菜单备份_*）恢复所有右键菜单项。\n是否继续？',
      '确认恢复'
    );
    if (!ok) return;
    try {
      if (window.api?.contextmenu) {
        const resp = await window.api.contextmenu.restore();
        if (!resp.success) throw new Error(resp.message);
        const d = resp.data || {};
        const n = Number(d.imported || 0) + Number(d.restored || 0);
        window.app?.toast('success', `已从 ${d.backupDir} 恢复 ${n} 项`);
        // CM-9：旧版本产出的备份头是 HKCR，导入会落到 HKLM，服务端一律拒收并回报 skipped。
        // 这种情况必须如实告诉用户，不能让他以为「恢复成功了」。
        if (Number(d.skipped || 0) > 0) {
          const reasons = Array.isArray(d.skipReasons) ? d.skipReasons.slice(0, 3).join('；') : '';
          window.app?.toast('warning', `有 ${d.skipped} 个备份被拒绝导入（备份头不是真实注册表分支，多为旧版本产生）${reasons ? '：' + reasons : ''}`, 6000);
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

  // ==================== 侧边栏分类树导航（树状分组，选中项持久化） ====================
  const CATEGORY_STORAGE_KEY = 'winclean-ctx-category';

  function getStoredCategory() {
    try {
      const saved = localStorage.getItem(CATEGORY_STORAGE_KEY);
      // 仅接受合法分类（防止残留旧值）
      return saved && SIDEBAR_CATEGORY_MATCH[saved] ? saved : '文件';
    } catch (e) {
      return '文件';
    }
  }

  function storeCategory(cat) {
    try { localStorage.setItem(CATEGORY_STORAGE_KEY, cat); } catch (e) {}
  }

  // 分类树子项高亮（圆点 + 底色，与测速分组视觉一致）
  function applyCategoryNavActive() {
    document.querySelectorAll('#ctxCategoryNav [data-category]').forEach(el => {
      el.classList.toggle('active', el.dataset.category === currentCategory);
    });
  }

  function setCategory(cat) {
    if (!SIDEBAR_CATEGORY_MATCH[cat]) return;
    currentCategory = cat;
    storeCategory(cat);
    applyCategoryNavActive();
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
  }

  // ==================== 批次 B：Win11 菜单形态 ====================
  let win11Mode = '';

  function setWin11ModeText(mode) {
    const el = document.getElementById('ctxWin11Mode');
    if (!el) return;
    el.textContent = mode === 'classic' ? '经典完整菜单' : (mode === 'modern' ? '新版精简菜单' : '读取失败');
  }

  async function loadWin11Mode() {
    if (!window.api?.contextmenu?.win11Mode) { setWin11ModeText(''); renderWin11Switch(); return; }
    try {
      const resp = await window.api.contextmenu.win11Mode('get');
      win11Mode = (resp && resp.success && resp.data && resp.data.mode) || '';
    } catch (e) { win11Mode = ''; }
    setWin11ModeText(win11Mode);
    renderWin11Switch();
  }

  // ds 未加载时优雅降级成一个普通按钮（红线：不得因为缺件就整块不渲染）
  function renderWin11Switch() {
    const mount = document.getElementById('ctxWin11Switch');
    if (!mount) return;
    mount.textContent = '';
    if (!win11Mode) {
      const hint = document.createElement('span');
      hint.className = 'ctx-blocked-empty';
      hint.textContent = '当前系统读不到该开关（可能不是 Windows 11，或键被组策略锁定）。';
      mount.appendChild(hint);
      return;
    }
    const wantClassic = win11Mode === 'classic';
    // ds.switch 返回的是 { el, input, set } 包装对象，不是元素本身，必须取 .el 再挂载
    if (window.ds && typeof window.ds.switch === 'function') {
      const sw = window.ds.switch({
        checked: wantClassic,
        label: '经典完整菜单',
        title: '仅对当前用户生效，切换后需重启资源管理器',
        id: 'ctxWin11ClassicSw',
        onChange: (checked) => { onWin11Switch(!!checked); }
      });
      mount.appendChild(sw.el);
      const cap = document.createElement('span');
      cap.className = 'ctx-mode-caption';
      cap.textContent = wantClassic
        ? '开 = 经典完整菜单（扩展全部平铺）'
        : '关 = 新版精简菜单（扩展折叠进「显示更多选项」）';
      mount.appendChild(cap);
      return;
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary';
    btn.textContent = wantClassic ? '切回新版精简菜单' : '切换到经典完整菜单';
    btn.addEventListener('click', () => { onWin11Switch(!wantClassic); });
    mount.appendChild(btn);
  }

  async function onWin11Switch(checked) {
    const target = checked ? 'classic' : 'modern';
    if (target === win11Mode) return;
    const ok = await window.app?.confirm(
      checked ? '切换到经典完整菜单' : '切换回新版精简菜单',
      checked
        ? '所有右键扩展将直接平铺在菜单里（等同 Windows 10 行为），不再折叠进「显示更多选项」。\n\n只改当前用户的注册表，随时可切回。'
        : '恢复 Windows 11 默认形态：菜单精简，第三方扩展折叠进「显示更多选项」。\n\n会删除当前用户下的那个开关键（HKLM 的系统默认不动）。',
      '确认切换'
    );
    // 取消或失败都要把开关拨回真实状态，否则 UI 与注册表不一致
    if (!ok) { renderWin11Switch(); return; }
    try {
      const resp = await window.api.contextmenu.win11Mode(target === 'classic' ? 'set-classic' : 'set-modern');
      if (resp && resp.success && resp.data) {
        win11Mode = resp.data.mode || target;
        if (resp.data.requireRestart) markPendingApply(1);
        window.app?.toast(resp.data.changed ? 'success' : 'info', resp.data.message || '已切换');
      } else {
        window.app?.toast('error', (resp && resp.message) || '切换失败');
      }
    } catch (e) {
      window.app?.toast('error', '切换失败: ' + e.message);
    }
    setWin11ModeText(win11Mode);
    renderWin11Switch();
  }

  // ==================== 批次 B：Shell Extensions\Blocked 可视化 ====================
  let blockedEntries = [];

  function blockedNameOf(guid) {
    const g = String(guid || '').toUpperCase();
    const hit = items.find(it => String(it.clsid || '').toUpperCase() === g);
    return hit ? hit.name : '';
  }

  async function loadBlockedList() {
    if (!window.api?.contextmenu?.blockedList) return;
    try {
      const resp = await window.api.contextmenu.blockedList();
      blockedEntries = (resp && resp.success && resp.data && Array.isArray(resp.data.entries)) ? resp.data.entries : [];
    } catch (e) { blockedEntries = []; }
    renderBlockedList();
  }

  function renderBlockedList() {
    const list = document.getElementById('ctxBlockedList');
    const countEl = document.getElementById('ctxBlockedCount');
    if (countEl) countEl.textContent = blockedEntries.length ? `${blockedEntries.length} 项` : '空';
    if (!list) return;
    if (!blockedEntries.length) {
      list.innerHTML = '<div class="ctx-blocked-empty">屏蔽表为空：没有扩展被 Shell Extensions\\Blocked 拦下。</div>';
      return;
    }
    list.innerHTML = blockedEntries.map((e, i) => {
      const name = blockedNameOf(e.guid);
      // 解除屏蔽复用启停通道，而主进程只认最近一次扫描的快照 —— 不在扫描结果里的 GUID
      // 无法通过校验，因此只展示、不给按钮（多为已卸载软件的遗留登记）。
      const known = !!name;
      const label = known ? escapeHtml(name) : '未在扫描结果中（多为已卸载软件的遗留登记）';
      const scope = e.scope === 'machine' ? 'HKLM' : 'HKCU';
      return `<div class="ctx-blocked-row">
        <span class="ctx-blocked-name" data-tip="${escapeHtml(e.guid)}">${label}</span>
        <span class="ctx-blocked-guid mono">${scope}</span>
        ${known ? `<button type="button" class="btn btn-secondary" data-blocked-unblock="${i}" data-tip="从屏蔽表移除该 GUID，恢复加载">解除屏蔽</button>` : ''}
      </div>`;
    }).join('');
    list.querySelectorAll('[data-blocked-unblock]').forEach(btn => {
      btn.addEventListener('click', () => { unblockEntry(Number(btn.dataset.blockedUnblock)); });
    });
  }

  async function unblockEntry(idx) {
    const entry = blockedEntries[idx];
    if (!entry) return;
    const item = items.find(it => String(it.clsid || '').toUpperCase() === String(entry.guid).toUpperCase());
    if (!item) { window.app?.toast('info', '该项不在最近一次扫描结果里，请先重新扫描'); return; }
    if (entry.scope === 'machine') {
      const elevated = await window.app?.requestElevation?.('解除机器级屏蔽需要管理员权限（写入 HKLM 屏蔽表）。');
      if (!elevated) return;
    }
    await applyToggles([{ item, enabled: true }]);
    await loadBlockedList();
  }

  function toggleModePanel() {
    const panel = document.getElementById('ctxModePanel');
    const btn = document.getElementById('btnCtxModePanel');
    if (!panel) return;
    panel.hidden = !panel.hidden;
    if (btn) btn.setAttribute('aria-expanded', panel.hidden ? 'false' : 'true');
    // 展开时才拉数据：屏蔽表与菜单形态都是实时读注册表，不必在进页面时就阻塞扫描
    if (!panel.hidden) { loadWin11Mode(); loadBlockedList(); }
  }

  function init() {
    // 「扫描」按钮 = 强制真实扫描并覆盖缓存（v3.2.1 缓存政策）
    document.getElementById('btnScanContext')?.addEventListener('click', () => scan(true));
    document.getElementById('btnRestoreMenu')?.addEventListener('click', restore);
    // 批次 B：生效条与菜单形态面板
    document.getElementById('btnCtxRestartExplorer')?.addEventListener('click', restartExplorer);
    document.getElementById('btnCtxApplyDismiss')?.addEventListener('click', () => {
      pendingApply = 0;
      renderApplyBar();
      window.app?.toast('info', '改动已写入注册表，稍后可在资源管理器任务栏右键或重登后生效');
    });
    document.getElementById('btnCtxModePanel')?.addEventListener('click', toggleModePanel);
    renderApplyBar();
    // v3.2.1：进入页面自动加载缓存（首次无缓存时自动扫描一次并落盘）
    scan(false);

    document.querySelectorAll('#contextFilter .filter-tab').forEach(el => {
      el.addEventListener('click', () => setFilter(el.dataset.filter));
    });

    // 侧边栏分类树：点击子项切换分类筛选（与顶部筛选标签叠加生效，保留勾选状态；选中项持久化）
    currentCategory = getStoredCategory();
    applyCategoryNavActive();
    document.querySelectorAll('#ctxCategoryNav [data-category]').forEach(el => {
      el.addEventListener('click', () => {
        const cat = el.dataset.category;
        if (cat === currentCategory) return; // 点击当前激活项不重复刷新
        setCategory(cat);
        if (hasScanned && items.length) {
          const grouped = getGroupedItems();
          const count = Object.values(grouped).reduce((s, arr) => s + arr.length, 0);
          window.app?.toast('info', `已切换到「${cat}」分类，匹配 ${count} 项`);
        }
      });
    });
  }

  window.contextmenu = { init, scan, removeItem, restore, MOCK_ITEMS, CATEGORY_ORDER, openDetail };
})();
