// cleanup.js - C 盘清理模块
// 实现扫描、勾选、清理、进度显示
(function () {
  'use strict';

  // 分类定义：唯一数据源为 src-tauri/data/cleanup-rules.json（编译期内嵌，不随前端目录分发）（P1-9 数据化）。
  // Electron 运行时经 IPC（cleanup.rules）读取该 JSON 构建 CATEGORIES；
  // 下方 FALLBACK 副本仅用于浏览器预览模式与 IPC 不可用时的兜底。
  // Windows 系统采用二级菜单分类（参考截图），其它仍为扁平。
  // 审查 2-2：FALLBACK 改为构建期生成——原始规则 JSON 由 cleanup-fallback.generated.js 提供
  // （scripts/gen-fallback.js 产出，勿手改），经与 IPC 相同的 buildCategoriesFromRules 构建，
  // 从结构上消除「FALLBACK 副本与规则 JSON 双源漂移」。改规则后重新生成即可，无需手工同步。
  // 复核 J-5（2026-09-16）：内置 fallback JSON 结构异常时不再阻断整脚本加载（原直接调用
  // 会抛错并连带扫描/执行 UI 全部失效），降级为空分类继续运行。
  const CATEGORIES_FALLBACK = (() => {
    try {
      return buildCategoriesFromRules(
        (typeof window !== 'undefined' ? window : globalThis).CLEANUP_RULES_FALLBACK || { groups: [] }
      );
    } catch (e) {
      console.warn('内置清理规则兜底构建失败，已降级为空分类:', e);
      return [];
    }
  })();

  // 从 cleanup-rules.json 的分组项提取渲染层所需字段（id/name/risk/fileCleanType/domain/nature）
  // v3.2.1 类目重构：domain/group 为唯一分类主轴元数据，nature 为性质标签（文档 §3.1）
  // F4a1-M01（v7.2 C06）：后端对 risk=high 强制的两个告知字段必须原样带进渲染层——
  // `ifDeleted`（删除后果，rules.rs 对高危装载即拒空）与 `evidenceItems`（依据逐条）。
  // 旧实现把两者裁掉，导致「高危必须告知」的后端硬闸在界面上永不可见。
  function pickRuleItem(it) {
    const o = { id: it.id, name: it.name, risk: it.risk };
    if (it.fileCleanType) o.fileCleanType = it.fileCleanType;
    if (it.domain) o.domain = it.domain;
    if (it.nature) o.nature = it.nature;
    if (it.ifDeleted) o.ifDeleted = it.ifDeleted;
    if (Array.isArray(it.evidenceItems) && it.evidenceItems.length) {
      o.evidenceItems = it.evidenceItems.map(e => ({ weight: e.weight, text: e.text }));
    }
    return o;
  }

  // 将 JSON 的 groups 数组转换为按 key 索引的 CATEGORIES 对象（与 FALLBACK 形状一致）
  function buildCategoriesFromRules(rules) {
    const out = {};
    for (const g of rules.groups) {
      const group = { title: g.title, icon: g.icon };
      if (Array.isArray(g.subGroups)) {
        group.subGroups = g.subGroups.map(sg => ({
          id: sg.id, name: sg.name, icon: sg.icon,
          items: sg.items.map(pickRuleItem)
        }));
      } else if (Array.isArray(g.items)) {
        group.items = g.items.map(pickRuleItem);
      }
      out[g.key] = group;
    }
    return out;
  }

  // 运行时生效的分类定义：默认用 FALLBACK，Electron 下由 init() 经 IPC 从 JSON 覆盖。
  let CATEGORIES = CATEGORIES_FALLBACK;

  // 性能 v3 ③：id -> 归属索引。原 getItemById / groupKeyForItem 每次线性扫全库
  // （规则库现算 5 组 / 22 子组 / 187 条 ⇒ 一次扫描约 7 万次比较），且 groupKeyForItem
  // 每组都调 getGroupItems ⇒ 每次分配约 10 个临时数组。
  // 铁律：索引**只存原始条目**（item 直接引用 CATEGORIES 里的对象，不复制、不裁剪），
  // 「是否可见」的判定留在调用侧走 hiddenIds —— 在索引里烘焙可见性会把 detect 未命中项
  // 从分组计数口径里静默改掉（updateGroupSummary 的 totalItems 口径就变了）。
  // 命中顺序与旧的 Object.values(CATEGORIES) 遍历一致：同一 id 重复出现时**先到先得**
  // （原 getItemById 的 .find() / groupKeyForItem 的 .some() 都是取第一个命中组）。
  let itemIndex = new Map();
  function rebuildItemIndex() {
    const next = new Map();
    for (const [groupKey, group] of Object.entries(CATEGORIES)) {
      if (group.subGroups) {
        for (const sg of group.subGroups) {
          for (const item of sg.items) {
            if (!next.has(item.id)) {
              next.set(item.id, { groupKey, group: group.title, subGroup: sg.name, subGrouped: true, item });
            }
          }
        }
      } else if (group.items) {
        for (const item of group.items) {
          if (!next.has(item.id)) {
            next.set(item.id, { groupKey, group: group.title, subGrouped: false, item });
          }
        }
      }
    }
    itemIndex = next;
  }
  rebuildItemIndex(); // CATEGORIES 的每个赋值点都要跟着重建（另一处见 loadRulesFromMain）

  // 展平所有分类的 id（用于一键扫描 / 全选）
  function getAllIds() {
    const ids = [];
    for (const group of Object.values(CATEGORIES)) {
      if (group.subGroups) {
        for (const sg of group.subGroups) {
          for (const it of sg.items) ids.push(it.id);
        }
      } else if (group.items) {
        for (const it of group.items) ids.push(it.id);
      }
    }
    return ids;
  }
  let ALL_IDS = getAllIds(); // IPC 覆盖 CATEGORIES 后在 init() 中重算

  // 模拟数据（用于浏览器预览模式）
  const MOCK_SIZES = {
    // Windows 系统二级分类
    dismPlusOld: 89 * 1024 * 1024,
    chromeOldBackup: 128 * 1024 * 1024,
    wpsOldBackup: 234 * 1024 * 1024,
    windowsReport: 67 * 1024 * 1024,
    windowsUpdateLog: 45 * 1024 * 1024,
    diagnosisData: 220 * 1024 * 1024,
    windowsDownloadCache: 1024 * 1024 * 1024,
    deliveryOptimization: 234 * 1024 * 1024,
    terminalServerCache: 18 * 1024 * 1024,
    dotNetCache: 45 * 1024 * 1024,
    prefetchFiles: 89 * 1024 * 1024,
    thumbnailCacheFiles: 234 * 1024 * 1024,
    winINetCache: 156 * 1024 * 1024,
     winINetCookies: 23 * 1024 * 1024,
     userCrashDumps: 76 * 1024 * 1024,
    packageCache: 567 * 1024 * 1024,
    defenderHistoryRecords: 89 * 1024 * 1024,
    windowsLogs: 89 * 1024 * 1024,
    tempFiles: 567 * 1024 * 1024,
    driverTempExtract: 123 * 1024 * 1024,
    qqTemp: 234 * 1024 * 1024,
    baiduNetdiskLog: 156 * 1024 * 1024,
    recycleBin: 89 * 1024 * 1024,
    memoryDumpFiles: 345 * 1024 * 1024,
     dismComponentCleanup: 0,
    // 显卡 / 浏览器 / 应用
    nvidiaCache: 345 * 1024 * 1024,
    amdCache: 234 * 1024 * 1024,
    intelShaderCache: 67 * 1024 * 1024,
    chromeCache: 567 * 1024 * 1024,
     chromeCodeCache: 234 * 1024 * 1024,
     chromeMediaCache: 96 * 1024 * 1024,
     edgeMediaCache: 84 * 1024 * 1024,
     edgeCache: 345 * 1024 * 1024,
    steamCache: 890 * 1024 * 1024,
    neteaseMusicCache: 386 * 1024 * 1024,
    wechatCache: 742 * 1024 * 1024,
    qqCache: 456 * 1024 * 1024,
    douyinCache: 518 * 1024 * 1024,
    qqFileClean: 890 * 1024 * 1024,
    wechatFileClean: 1234 * 1024 * 1024
  };

  const MOCK_PATHS = {
    neteaseMusicCache: '%LOCALAPPDATA%\\NetEase\\CloudMusic\\Cache',
    wechatCache: '%USERPROFILE%\\Documents\\xwechat_files',
    qqCache: '%APPDATA%\\Tencent\\QQ\\Cache',
    douyinCache: '%LOCALAPPDATA%\\Douyin',
    qqFileClean: '%USERPROFILE%\\Documents\\Tencent Files',
    wechatFileClean: '%USERPROFILE%\\Documents\\xwechat_files'
  };

  // 文件清理项 ID（使用独立扫描/清理逻辑）
  const FILECLEAN_IDS = ['qqFileClean', 'wechatFileClean'];

  // G-4（2026-10-07）：回收站条目的 id。它是**唯一**不走常规清理链的条目 ——
  // 清空走系统 Shell API（cleanup:empty-recycle-bin），体积由 cleanup:recycle-stats 现查。
  // 规则侧已撤掉 `pathPs`（不再把 $Recycle.Bin 当普通目录永久删），引擎只发一条
  // size=0 的占位行（native-scanner 的 emit_recycle_bin）。判据集中在这一个常量上，
  // 不要在别处再写字符串字面量。
  const RECYCLE_ID = 'recycleBin';

  // P1 安装检测（detect）未命中的条目：扫描后从列表隐藏（重新扫描/换规则后自动恢复）
  const hiddenIds = new Set();
  function visibleItems(items) { return items.filter(i => !hiddenIds.has(i.id)); }

  // 状态
  let scanResults = new Map();
  let selectedIds = new Set();
  let isScanning = false;
  let isCleaning = false;
  // P1-7：确认期间的重复点击标志（在任何 await 之前同步置起、在 finally 复位）。
  let confirmInFlight = false;
  // 2026-10-12：执行期逐项进度的接收器。订阅一次性注册在 init()（onEvent 会累积，
  // 不能放进 clean()）；每次执行时挂上真实处理器、结束置空，见 clean()。
  let execProgressSink = null;
  // 文件清理扫描结果：id -> { files: [...], totalSize, scanPath }
  let fileCleanData = new Map();

  // 工具：把任意后端 size 收敛成有限非负数。字符串、NaN、Infinity 一律归零，
  // 否则裸 `+` 会把累加器变成字符串或 Infinity（v2 尺寸异常根因的放大器）。
  function sizeNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  // 工具：格式化字节 —— P3-5（F4a-M01）：本地实现并轨真源 ds.fmtBytes（AGENTS §2
  // 红线「字节格式化唯一真源」；原实现自带 1024 边界假值的独立舍入口径）。
  function formatSize(bytes) { return window.ds.fmtBytes(bytes); }

  function getItemById(id) {
    const hit = itemIndex.get(id);
    if (!hit) return null;
    // 键集合与旧实现逐一对应：只有走 subGroups 分支命中的条目才带 subGroup 键
    // （旧实现 flat 分支返回的是 `{ ...item, group }`，没有 subGroup 这个键）
    return hit.subGrouped
      ? { ...hit.item, group: hit.group, subGroup: hit.subGroup }
      : { ...hit.item, group: hit.group };
  }

  // 取某个 subGroup 的全部子项 id（已移除项不参与）
  // v3.2.1：不再硬编码 windows 组——遍历全部域的 subGroups（子分类 id 可能跨域同名，
  // 持久化折叠键已带组前缀，此处按「组内 sg.id」唯一性逐组查找第一个命中即可）
  function getSubGroupItemIds(subGroupId) {
    for (const group of Object.values(CATEGORIES)) {
      if (!group.subGroups) continue;
      const sg = group.subGroups.find(s => s.id === subGroupId);
      if (sg) return sg.items.map(i => i.id);
    }
    return [];
  }

  // ==================== P2 规模化浏览 ====================
  // 2026-09-28 仓库精简：搜索/筛选 UI（cleanFilterBar）已随九轮拍板整行删除，
  // filterState/filterActive/itemMatchesFilter 空转逻辑与绑定代码一并清除——
  // 此前筛选恒为「不过滤」，但每次渲染仍白跑三层 filter/map。

  // ==================== 详细信息表格（资源管理器风格） ====================
  const RISK_ORDER = { low: 0, medium: 1, high: 2 };
  const RISK_LABELS = { low: '安全', medium: '注意', high: '高风险' };

  // 每个表格独立的排序状态：tableKey -> {key, dir}
  const sortStates = {};
  // 折叠状态持久（重渲染/排序时保留）：'group:windows' / 'sub:outdated'
  const collapsedKeys = new Set();
  let defaultCollapsedInitialized = false;

  const COL_CHECK = { key: 'check', label: '', width: 40, minWidth: 40, sortable: false, resizable: false };
  const COL_NAME = { key: 'name', label: '名称', width: 220, minWidth: 100 };
  const COL_PATH = { key: 'path', label: '路径', minWidth: 140 };
  // v3.2.1 类目重构 S2：性质标签列（缓存/日志/临时/转储/隐私/更新残留/过时备份/动作）
  const COL_NATURE = { key: 'nature', label: '性质', width: 76, minWidth: 64, align: 'center' };
  const COL_RISK = { key: 'risk', label: '风险', width: 84, minWidth: 64, align: 'center' };
  // 160：回收站行要并显示「体积 + · N 个条目」两段文本。110 时该行放不下，
  // 而 flex-end + overflow:hidden 的溢出发生在左端、体积数值被整段裁掉
  // （用户 2026-10-07 目检缺陷 1「只显示『GB · 555 个条目』」）。
  const COL_SIZE = { key: 'size', label: '占用大小', width: 160, minWidth: 84, align: 'end' };
  const COL_ACTIONS = { key: 'actions', label: '操作', width: 112, minWidth: 84, sortable: false, align: 'center' };

  const NATURE_LABELS = {
    cache: '缓存', log: '日志', temp: '临时', dump: '转储',
    history: '隐私', updateResidual: '更新残留', staleBackup: '过时备份',
    action: '动作', fileClean: '文件'
  };

  function columnsFor(groupKey) {
    // P3：全部分组都提供「明细」操作列（fileclean 组沿用图片预览按钮）
    const cols = [COL_CHECK, COL_NAME, COL_PATH, COL_NATURE, COL_RISK, COL_SIZE, COL_ACTIONS];
    return cols;
  }

  // 各列排序取值函数
  const SORT_FNS = {
    name: it => it.name,
    path: it => (scanResults.get(it.id) || {}).path || null,
    nature: it => NATURE_LABELS[it.nature] || '',
    risk: it => (RISK_ORDER[it.risk] !== undefined ? RISK_ORDER[it.risk] : 0),
    size: it => {
      const r = scanResults.get(it.id);
      return r && r.size !== null && r.size !== undefined ? r.size : null;
    }
  };

  function getSortState(tableKey) {
    if (!sortStates[tableKey]) sortStates[tableKey] = { key: null, dir: 'asc' };
    return sortStates[tableKey];
  }

  function escapeHtml(s) { return window.ds.esc(s); }

  // 跨条目重复计账扣减（唯一口径，所有汇总走它）。后端把「两条 item 覆盖到同一批文件」
  // 配成无序对挂在后到的一条上（overlapsWith）；只有**两端都在本次求和集合内**才扣，
  // 所以只勾父条时父条照报满、不会为去重而虚低。
  // 真机依据（2026-10-22 gfx 15 项）：nvidiaCache 整树报的 387,378,791 B 与
  // nvidiaShaderCache 清单里同树的 162 个文件逐字节相等，逐条相加虚高到 1.61×
  //（界面 976 MB、真实可清 607 MB）。
  // 已知边界：配对只覆盖**本次扫描范围内的条目**——只重扫子集会丢掉跨批次的配对，
  // 那一档退回相加口径（只会偏大、回到旧行为，不会把可清量报小）。全量扫描后即为准确值。
  function dedupSize(ids) {
    const set = ids instanceof Set ? ids : new Set(ids);
    let total = 0;
    for (const id of set) total += sizeNumber(scanResults.get(id)?.size);
    for (const id of set) {
      for (const o of (scanResults.get(id)?.overlapsWith) || []) {
        if (set.has(o.with)) total -= sizeNumber(o.bytes);
      }
    }
    return total > 0 ? total : 0;
  }

  function groupTotalSize(items) {
    return dedupSize(items.map((i) => i.id));
  }

  function toggleCollapsible(group, content, key) {
    if (!group || !content) return;
    const willExpand = group.classList.contains('collapsed');
    if (key) {
      if (willExpand) collapsedKeys.delete(key); else collapsedKeys.add(key);
    }
    if (willExpand) {
      group.classList.remove('collapsed');
      content.style.maxHeight = '0px';
      requestAnimationFrame(() => {
        content.style.maxHeight = `${content.scrollHeight}px`;
        // Electron 强制回流补丁：读取 offsetHeight 触发 Chromium 立即重排，
        // 修复窗口使用 transparent/backgroundMaterial + 滚动容器 + max-height
        // 动画时，DOM 已展开但子项数据行布局未刷新、视觉空白的问题。
        void content.offsetHeight;
        // 虚拟滚动重算：折叠期间容器高度为 0，虚拟列表只渲染了缓冲行，
        // 展开后无滚动事件触发，需主动 render 恢复完整可视行
        virtualLists.forEach(v => { try { v.render(); } catch (e) {} });
      });
      // 动画结束后释放 maxHeight，避免内容被固定高度裁剪（grid 布局未完成时 scrollHeight 偏小）
      setTimeout(() => {
        if (!group.classList.contains('collapsed')) {
          content.style.maxHeight = '';
          void content.offsetHeight;
          virtualLists.forEach(v => { try { v.render(); } catch (e) {} });
        }
      }, 360);
      return;
    }

    content.style.maxHeight = `${content.scrollHeight}px`;
    requestAnimationFrame(() => {
      group.classList.add('collapsed');
      content.style.maxHeight = '0px';
    });
  }

  // 渲染一张表格：表头（排序/列宽）+ 数据行
  // 虚拟滚动（windowing）：body 留空，完整 rows 进入待办队列，由 renderCategoryList
  // 末尾统一挂载 createVirtualList，只渲染视口附近行（取代「分批 + 加载更多」）。
  let pendingBatches = []; // [{ tableKey, groupKey, columns, rows }]
  let virtualLists = [];   // 正在生效的虚拟滚动实例（重渲染前统一销毁，防 resize 监听泄漏）
  let rowDelegationBound = false; // 行点击/预览的容器级委托是否已绑定（一次性）

  function renderTable(groupKey, items, tableKey) {
    const columns = columnsFor(groupKey);
    const state = getSortState(tableKey);
    const sorted = xtable.sortItems(items, state, SORT_FNS);
    const head = xtable.renderHeader(columns, state);
    pendingBatches.push({ tableKey, groupKey, columns, rows: sorted });
    return `<div class="xtable xtable-virtual" data-table="${window.ds.escAttr(tableKey)}" data-group-key="${window.ds.escAttr(groupKey)}">${head}<div class="xtable-body"></div></div>`;
  }

  function previewBtnHtml(item, hasImages, imageCount) {
    return `<button class="fileclean-preview-btn" data-preview="${window.ds.escAttr(item.id)}" ${hasImages ? '' : 'disabled'} data-tip="${hasImages ? `预览 ${imageCount} 张图片` : '无可预览图片'}">
      <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>
      预览${hasImages ? ` (${imageCount})` : ''}
    </button>`;
  }

  // 排除名单只覆盖文件系统路径（正侧匹配防误判）：盘符 / UNC / %环境变量% 开头。
  // 渲染单个数据行（列布局样式与表头共用 buildLayout，保证对齐）
  function renderRow(item, columns, groupKey) {
    const layout = xtable.buildLayout(columns);
    const result = scanResults.get(item.id);
    const size = result ? result.size : null;
    const isSelected = selectedIds.has(item.id);
    const isFileClean = FILECLEAN_IDS.includes(item.id);
    const hasImages = isFileClean && fileCleanData.has(item.id) &&
      fileCleanData.get(item.id).files.some(f => f.category === 'image');
    const imageCount = isFileClean && fileCleanData.has(item.id)
      ? fileCleanData.get(item.id).files.filter(f => f.category === 'image').length
      : 0;

    const cells = layout.map(({ col, style }) => {
      let inner = '';
      switch (col.key) {
        case 'check':
          // P3-1（可达性）：三属性同现（role/tabindex/aria-checked），键盘 Space 激活
          // 由 ds.bindCheckboxKeys 合成 click；aria-checked 在 updateUI 里随选中态同步
          // F4a1-L04：role=checkbox 必须有可访问名——行是 div 非表格语义，读屏
          // 只报「复选框，未选中」说不出是哪一项，aria-label 显式给条目名。
          inner = `<div class="checkbox ${isSelected ? 'checked' : ''}" data-checkbox="${window.ds.escAttr(item.id)}" role="checkbox" tabindex="0" aria-checked="${isSelected ? 'true' : 'false'}" aria-label="${escapeHtml(item.name)}"></div>`;
          break;
        case 'name': {
          // 中缝省略：超长文件名保留首尾（title 仍展示完整原文）
          // P1-A3（2026-10-01）：悬停依据升级为贡献项逐条展示——正分事实标「＋」，
          // 0 分解释项标「·」（只解释执行方式，不改变建议分量）。内容全部来自
          // 规则条目已登记的字段事实；没有 evidenceItems 的条目回退为只显示全名。
          const evs = Array.isArray(item.evidenceItems) && item.evidenceItems.length
            ? item.evidenceItems
            : null;
          const tipLines = [item.name];
          if (evs) {
            tipLines.push('依据：');
            for (const ev of evs) {
              tipLines.push((ev.weight > 0 ? '＋ ' : '· ') + (ev.text || ''));
            }
          }
          // P2-1（2026-10-16）：删除后果（ifDeleted）进同一枚 tooltip——high 必填、
          // medium 可选、low 不强制；高危条目悬停即见「删了会怎样」。复用既有详情面，
          // 不新增视觉 token；文本随整串经 escapeHtml（= ds.esc）转义。
          if (item.ifDeleted) {
            tipLines.push('删除后果：');
            tipLines.push(item.ifDeleted);
          }
          // F4a1-M01 残留射程（2026-10-23）：data-tip 的展示判据含 focusin，但无 tabindex
          // 的 span 拿不到焦点 ⇒ 键盘/读屏用户永远看不到后果。只对**确实写了后果**的条目
          // 开放焦点（现算全库 3 条），不给 187 行的每个名称格都加停靠点。
          const focusable = item.ifDeleted ? ' tabindex="0"' : '';
          inner = `<span class="xtable-cell-text"${focusable} data-tip="${escapeHtml(tipLines.join('\n'))}">${escapeHtml(xtable.middleEllipsis(item.name, 40))}</span>`;
          break;
        }
        case 'path':
          if (result && result.path) {
            const autoTag = result.pathSource === 'auto' ? ' <span class="path-auto-tag">自动定位</span>' : '';
            // P1：fileKeys/regKeys 条目的规模标签 + requiredStoppedProcesses 命中提示标签
            const fileTag = result.fileCount > 0 ? ` <span class="path-auto-tag">共 ${result.fileCount} 个文件</span>` : '';
            const regTag = result.regCount > 0 ? ` <span class="path-auto-tag">注册表 ${result.regCount} 项</span>` : '';
            const blockedTag = Array.isArray(result.blockedBy) && result.blockedBy.length
              ? ` <span class="path-blocked-tag" data-tip="执行前会跳过此项目并提示原因">需关闭: ${escapeHtml(result.blockedBy.join(', '))}</span>` : '';
            // R1-2：跳过 junction 必须让用户看见。不说的话，扫描结果天然比 Explorer 算的少，
            // 用户会去手工核对目录、怀疑扫描漏了。复用 path-auto-tag（既有 token，零新增样式）。
            const reparseTag = Number(result.skippedReparse) > 0
              ? ` <span class="path-auto-tag" data-tip="扫描时跳过了 ${escapeHtml(String(result.skippedReparse))} 个联接点/挂载点目录（它们指向别的子树，深入会重复计数）">已跳过 ${escapeHtml(String(result.skippedReparse))} 个联接点</span>` : '';
            // A1-M02：读不到的目录同样必须可见——否则「扫描失败」会被读成「没有可清理项」。
            const unreadableTag = Number(result.skippedUnreadable) > 0
              ? ` <span class="path-auto-tag" data-tip="扫描时有 ${escapeHtml(String(result.skippedUnreadable))} 个目录读不到（权限或 IO 失败），候选清单可能不完整">${escapeHtml(String(result.skippedUnreadable))} 个目录不可读</span>` : '';
            // 2026-10-04 审计 §4.3：filesTruncated 此前标记了但渲染层零消费 —— 清单被
            // 截断意味着确认时看到的文件数 < 实际将清理的文件数，必须在行上可见。
            const truncTag = result.filesTruncated
              ? ' <span class="path-auto-tag" data-tip="文件清单超出单次上限被截断，实际清理范围可能大于所列">清单已截断</span>' : '';
            inner = `<span class="xtable-cell-text xtable-cell-path" data-tip="${escapeHtml(result.path)}">${escapeHtml(xtable.middleEllipsis(result.path, 72))}${autoTag}${fileTag}${regTag}${reparseTag}${unreadableTag}${truncTag}${blockedTag}</span>`;
          } else {
            inner = '<span class="xtable-cell-muted">—</span>';
          }
          break;
        case 'nature':
          inner = item.nature
            ? `<span class="nature-tag nature-${escapeHtml(item.nature)}">${NATURE_LABELS[item.nature] || escapeHtml(item.nature)}</span>`
            : '<span class="xtable-cell-muted">—</span>';
          break;
        case 'risk':
          // F4a1-L01：risk 是规则库封闭枚举（low/medium/high），今天没有实际注入面，
          // 但同一函数里 nature 侧已走转义、这里却两侧直插——口径按「规则库字段渲染前
          // 一律转义」统一，枚举日后扩档不会变成 class/text 双注入面。
          inner = `<span class="category-risk ${window.ds.escAttr(item.risk)}">${escapeHtml(RISK_LABELS[item.risk] || item.risk)}</span>`;
          break;
        case 'size': {
          let sizeInner = size !== null && size !== undefined ? formatSize(size) : '<span class="xtable-cell-muted">—</span>';
          // G-4 追补（用户 2026-10-07 反馈「只显示体积、条目数一直不出来」）：recycleCount
          // 扫描时已由 cleanup:recycle-stats 现查赋值，但此前只有清空确认弹窗消费它——
          // 列表行从未渲染。方案 G-4 的承诺是「先出条目数与体积」，两处都要齐。
          if (item.id === RECYCLE_ID && result && Number(result.recycleCount) > 0) {
            // xtable-size-count：可收缩段，放不下时它出省略号，而不是把体积数值左裁（见 main.css）
            sizeInner += ` <span class="xtable-cell-muted xtable-size-count">· ${Number(result.recycleCount)} 个条目</span>`;
          }
          inner = sizeInner;
          break;
        }
        case 'actions':
          if (isFileClean) {
            inner = previewBtnHtml(item, hasImages, imageCount);
          } else if (item.id === RECYCLE_ID) {
            // G-4 修订（用户 2026-10-07 二次反馈「还是没有明细按钮」）：Shell 动作条目的
            // 「明细」不能弹出恒空清单，但可以打开系统回收站——条目清单由系统窗口承载
            // （自绘枚举要 IShellFolder 遍历，慢且权限面大），与清空同一 Shell 语义。
            inner = '<button class="fileclean-preview-btn" data-open-recycle type="button" data-tip="回收站条目由系统管理，点击打开系统回收站查看">明细</button>';
          } else {
            // P3：明细按钮——弹窗枚举该条目将删除的具体文件清单（只读）
            inner = `<button class="fileclean-preview-btn" data-detail="${window.ds.escAttr(item.id)}" data-tip="查看此条目包含的具体文件清单（只读，最多展示 600 条）">明细</button>`;
          }
          break;
      }
      const align = col.align === 'end' ? ' data-align="end"' : (col.align === 'center' ? ' data-align="center"' : '');
      return `<div class="xtable-td" data-cell="${col.key}" style="${style}"${align}>${inner}</div>`;
    }).join('');

    return `<div class="xtable-row" data-id="${window.ds.escAttr(item.id)}">${cells}</div>`;
  }

  // 渲染分类列表（表格视图，支持二级分类）
  function renderCategoryList() {
    const container = document.getElementById('categoryList');
    if (!container) return;
    // 首次进入磁盘清理保持紧凑折叠态；用户展开后的状态在会话内保留。
    if (!defaultCollapsedInitialized) {
      Object.entries(CATEGORIES).forEach(([groupKey, group]) => {
        collapsedKeys.add('group:' + groupKey);
        if (Array.isArray(group.subGroups)) {
          group.subGroups.forEach(sg => collapsedKeys.add('sub:' + sg.id));
        }
      });
      defaultCollapsedInitialized = true;
    }
    virtualLists.forEach(v => v.destroy());
    virtualLists = [];
    container.innerHTML = '';
    pendingBatches = [];

    // 行点击/预览按钮：容器级事件委托（一次性绑定）。
    // #categoryList 节点跨重渲染持久（仅替换 innerHTML），委托监听器持续有效，
    // 分批追加的新行无需重新绑定事件。
    if (!rowDelegationBound) {
      rowDelegationBound = true;
      // P3-1（可达性）：勾选框（span/div 伪装控件）键盘激活 —— Space/Enter 合成 click，
      // 走下方既有的容器级 click 委托（[data-sub-checkbox] 有自己的 stopPropagation 处理器）
      window.ds.bindCheckboxKeys(container, '.checkbox');
      container.addEventListener('click', e => {
        const previewBtn = e.target.closest('.fileclean-preview-btn[data-preview]');
        if (previewBtn) {
          e.stopPropagation();
          if (!previewBtn.disabled) openPreview(previewBtn.dataset.preview);
          return;
        }
        const detailBtn = e.target.closest('[data-detail]');
        if (detailBtn) {
          e.stopPropagation();
          openItemDetail(detailBtn.dataset.detail);
          return;
        }
        const recycleBtn = e.target.closest('[data-open-recycle]');
        if (recycleBtn) {
          e.stopPropagation();
          openSystemRecycleBin();
          return;
        }
        const row = e.target.closest('.xtable-row');
        if (!row || !container.contains(row)) return;
        if (window.getSelection && window.getSelection().toString()) return;
        toggleSelection(row.dataset.id);
      });
    }

    let renderedAny = false;

    for (const [groupKey, rawGroup] of Object.entries(CATEGORIES)) {
      // P1：detect 未命中的隐藏条目不渲染（分组计数/大小汇总同步排除）
      const group = rawGroup.subGroups
        ? { ...rawGroup, subGroups: rawGroup.subGroups.map(sg => ({ ...sg, items: visibleItems(sg.items) })).filter(sg => sg.items.length > 0) }
        : { ...rawGroup, items: visibleItems(rawGroup.items || []) };
      if (!group.subGroups && !group.items.length) {
        continue;
      }
      // v3.2.1 类目重构：维护与特殊操作域加视觉隔离类（警示条 + 语义边界）
      const groupEl = document.createElement('div');
      groupEl.className = 'category-group'
        + (groupKey === 'fileclean' ? ' fileclean-group' : '')
        + (groupKey === 'special' ? ' special-group' : '');

      if (group.subGroups) {
        // 二级分类布局（各清理域）
        const subGroups = group.subGroups.filter(sg => sg.items.length > 0);
        const totalItems = subGroups.reduce((s, sg) => s + sg.items.length, 0);
        groupEl.innerHTML = `
          <div class="category-group-header" data-group-toggle="${window.ds.escAttr(groupKey)}">
            <span class="category-group-icon">${group.icon}</span>
            <span>${escapeHtml(group.title)}</span>
            <span style="margin-left:auto;font-size:11px;color:var(--fg-tertiary)" data-group-count="${window.ds.escAttr(groupKey)}">${totalItems} 项 · ${subGroups.length} 分类</span>
          </div>
          <div class="category-group-content" data-group-content="${window.ds.escAttr(groupKey)}">
            ${subGroups.map(sg => renderSubGroup(groupKey, sg)).join('')}
          </div>
        `;
      } else {
        // 扁平布局：维护与特殊操作域（special）自 2026-10-22 起直接以组顶层 items 承载四项，
        // 不再有「系统动作」子分组；其余四域仍走子组分支。旧版兜底数据同样落这里。
        const items = group.items;
        if (!items.length) continue;
        groupEl.innerHTML = `
          <div class="category-group-header" data-group-toggle="${window.ds.escAttr(groupKey)}">
            <span class="category-group-icon">${group.icon}</span>
            <span>${escapeHtml(group.title)}</span>
            <span style="margin-left:auto;font-size:11px;color:var(--fg-tertiary)" data-group-count="${window.ds.escAttr(groupKey)}">${items.length} 项</span>
          </div>
          <div class="category-group-content" data-group-content="${window.ds.escAttr(groupKey)}">
            ${renderTable(groupKey, items, groupKey)}
          </div>
        `;
      }

      container.appendChild(groupEl);
      renderedAny = true;
    }

    // 恢复折叠状态 + 设置展开内容高度（展开态不锁死 maxHeight，避免 grid 布局未完成时 scrollHeight 偏小导致内容被裁剪）
    container.querySelectorAll('.category-group').forEach(g => {
      const toggle = g.querySelector(':scope > .category-group-header');
      const content = g.querySelector(':scope > .category-group-content');
      if (!toggle || !content) return;
      const key = 'group:' + toggle.dataset.groupToggle;
      if (collapsedKeys.has(key)) {
        g.classList.add('collapsed');
        content.style.maxHeight = '0px';
      } else {
        content.style.maxHeight = '';
      }
    });
    container.querySelectorAll('.sub-group').forEach(sg => {
      const content = sg.querySelector(':scope > .sub-group-content');
      if (!content) return;
      const key = 'sub:' + sg.dataset.subGroup;
      if (collapsedKeys.has(key)) {
        sg.classList.add('collapsed');
        content.style.maxHeight = '0px';
      } else {
        content.style.maxHeight = '';
      }
    });

    // 表头交互（排序 + 列宽拖拽）
    container.querySelectorAll('.xtable').forEach(tbl => {
      const state = getSortState(tbl.dataset.table);
      xtable.bindHeader(tbl, state, () => renderCategoryList());
    });

    // 折叠头的键盘等价路径（A3-M03）：这些 div 头带 `cursor:pointer` 且只挂 click ⇒
    // 键盘用户既聚焦不了也按不动，磁盘清理页全部一级/二级分类折叠走不到。
    // 同一张表的表头折叠本来就有键盘通路（`xtable.js:48` 给 role=columnheader tabindex=0、
    // `:127` 挂 keydown），这里是同仓双口径的另一半，收在同一个局部函数里而不是两处各写。
    const bindCollapseKeys = (el) => {
      if (!el || el.matches('button,a,input') || el.hasAttribute('tabindex')) return;
      el.setAttribute('tabindex', '0');
      el.setAttribute('role', el.getAttribute('role') || 'button');
      el.addEventListener('keydown', (e) => {
        if ((e.key === 'Enter' || e.key === ' ') && e.target === el) {
          e.preventDefault();
          el.click();
        }
      });
    };

    // 绑定折叠：顶层分组
    container.querySelectorAll('[data-group-toggle]').forEach(el => {
      bindCollapseKeys(el);
      el.addEventListener('click', e => {
        if (e.target.closest('.checkbox') || e.target.closest('.xtable')) return;
        const group = el.closest('.category-group');
        toggleCollapsible(group, group.querySelector(':scope > .category-group-content'), 'group:' + el.dataset.groupToggle);
      });
    });

    // 绑定二级分类折叠
    container.querySelectorAll('[data-sub-toggle]').forEach(el => {
      bindCollapseKeys(el);
      el.addEventListener('click', e => {
        if (e.target.closest('.checkbox') || e.target.closest('.xtable')) return;
        const sg = el.closest('.sub-group');
        toggleCollapsible(sg, sg.querySelector(':scope > .sub-group-content'), 'sub:' + el.dataset.subToggle);
      });
    });

    // 绑定父级复选框（批量勾选/取消所有子项）
    container.querySelectorAll('[data-sub-checkbox]').forEach(cb => {
      cb.addEventListener('click', e => {
        e.stopPropagation();
        const sgId = cb.dataset.subCheckbox;
        const ids = getSubGroupItemIds(sgId);
        // 全部已勾 → 全不勾；任一未勾 → 全勾
        const allSelected = ids.every(id => selectedIds.has(id));
        if (allSelected) {
          ids.forEach(id => selectedIds.delete(id));
        } else {
          ids.forEach(id => selectedIds.add(id));
        }
        updateUI();
      });
    });

    // 虚拟滚动（windowing）：为每张表挂载 createVirtualList，只渲染视口附近行。
    // 行点击/预览已走容器委托，无需逐行重绑事件。
    pendingBatches.forEach(pb => {
      const bodyEl = container.querySelector(`.xtable[data-table="${pb.tableKey}"] .xtable-body`);
      if (!bodyEl) return;
      virtualLists.push(
        xtable.createVirtualList(bodyEl, {
          rows: pb.rows,
          renderRow: item => renderRow(item, pb.columns, pb.groupKey)
        })
      );
    });
    pendingBatches = [];
  }

  // 渲染单个二级分类（v3.2.1：tableKey 带域前缀——子分类 id 可跨域同名）
  // v3.3.3：右侧统计两行化——第一行「N/M 项 · 已选 X GB」（真·已选大小），第二行「可选 Y GB」
  //（该子分组全部项大小）。旧行为把全部项大小拼在「2/5 项」后有歧义，用户会误读为已选大小。
  function renderSubGroup(groupKey, sg) {
    return `
      <div class="sub-group" data-sub-group="${window.ds.escAttr(sg.id)}">
        <div class="sub-group-header" data-sub-toggle="${window.ds.escAttr(sg.id)}">
          <span class="sub-group-chevron">${chevronSvg()}</span>
          <div class="checkbox" data-sub-checkbox="${window.ds.escAttr(sg.id)}" role="checkbox" tabindex="0" aria-checked="false" aria-label="${escapeHtml(sg.name)}"></div>
          <span class="sub-group-name">${escapeHtml(sg.name)}</span>
          <span style="margin-left:auto;font-size:11px;color:var(--fg-tertiary);text-align:right;line-height:1.5" data-sub-meta="${window.ds.escAttr(sg.id)}"><span data-sub-meta-line1="${window.ds.escAttr(sg.id)}">${sg.items.length} 项</span><span data-sub-meta-line2="${window.ds.escAttr(sg.id)}" style="display:block"></span></span>
        </div>
        <div class="sub-group-content">
          ${renderTable(groupKey, sg.items, groupKey + ':' + sg.id)}
        </div>
      </div>
    `;
  }

  function chevronSvg() {
    return '<svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M16.59 8.59L12 13.17 7.41 8.59 6 10l6 6 6-6z"/></svg>';
  }

  function toggleSelection(id) {
    if (selectedIds.has(id)) {
      selectedIds.delete(id);
    } else {
      selectedIds.add(id);
    }
    updateUI();
  }

  function selectAll() {
    for (const id of ALL_IDS) selectedIds.add(id);
    updateUI();
  }

  function deselectAll() {
    selectedIds.clear();
    updateUI();
  }

  // 全选/全不选切换：已全选 → 全不选；否则 → 全选
  function toggleSelectAll() {
    const allSelected = ALL_IDS.length > 0 && ALL_IDS.every(id => selectedIds.has(id));
    if (allSelected) deselectAll();
    else selectAll();
  }

  // 同步全选按钮文字（全选 ⇄ 全不选）
  function updateSelectAllButton() {
    const text = document.getElementById('btnSelectAllText');
    if (!text) return;
    const allSelected = ALL_IDS.length > 0 && ALL_IDS.every(id => selectedIds.has(id));
    text.textContent = allSelected ? '全不选' : '全选';
  }

  // 收集所有分类下的子项（含二级分类；detect 未命中的隐藏项不参与数量/大小汇总）
  function getGroupItems(group) {
    const items = group.subGroups ? group.subGroups.flatMap(sg => sg.items) : (group.items || []);
    return visibleItems(items);
  }

  function updateUI() {
    // 子项复选框（P3-1：aria-checked 与视觉态同源同步，读屏才跟得上批量操作）
    document.querySelectorAll('[data-checkbox]').forEach(cb => {
      const id = cb.dataset.checkbox;
      const on = selectedIds.has(id);
      cb.classList.toggle('checked', on);
      cb.setAttribute('aria-checked', on ? 'true' : 'false');
    });

    // 父级（二级分类）复选框：none / indeterminate / all
    for (const group of Object.values(CATEGORIES)) {
      if (!group.subGroups) continue;
      for (const sg of group.subGroups) {
        const sgItems = sg.items;
        if (!sgItems.length) continue;
        const cb = document.querySelector(`[data-sub-checkbox="${sg.id}"]`);
        if (!cb) continue;
        cb.classList.remove('checked', 'indeterminate');
        const total = sgItems.length;
        const selected = sgItems.filter(i => selectedIds.has(i.id)).length;
        if (selected === 0) {
          // none
        } else if (selected === total) {
          cb.classList.add('checked');
        } else {
          cb.classList.add('indeterminate');
        }
        // P3-1：三段态映射到 ARIA（none/indeterminate/all → false/mixed/true）
        cb.setAttribute('aria-checked', selected === 0 ? 'false' : (selected === total ? 'true' : 'mixed'));
        // 元信息更新（v3.3.3 两行化：第一行数量+已选大小，第二行可选总大小）
        const metaEl = document.querySelector(`[data-sub-meta="${sg.id}"]`);
        const line1 = metaEl && metaEl.querySelector(`[data-sub-meta-line1="${sg.id}"]`);
        const line2 = metaEl && metaEl.querySelector(`[data-sub-meta-line2="${sg.id}"]`);
        if (line1 && line2) { // 双行结构由 renderSubGroup 渲染，缺失则跳过本条刷新
          const sgAllSize = dedupSize(sgItems.map(i => i.id));
          const sgSelected = sgItems.filter(i => selectedIds.has(i.id));
          const selSize = dedupSize(sgSelected.map(i => i.id));
          if (sgSelected.length > 0) {
            line1.textContent = selSize > 0
              ? `${sgSelected.length}/${sgItems.length} 项 · 已选 ${formatSize(selSize)}`
              : `${sgSelected.length}/${sgItems.length} 项`;
          } else {
            line1.textContent = `${sgItems.length} 项`;
          }
          line2.textContent = sgAllSize > 0 ? `可选 ${formatSize(sgAllSize)}` : '';
        }
      }
    }

    // 总览（去重后口径：跨条目重叠只算一次）
    const totalSize = dedupSize(selectedIds);
    const totalEl = document.getElementById('totalSize');
    const countEl = document.getElementById('selectedCount');
    if (totalEl) totalEl.textContent = formatSize(totalSize);
    if (countEl) countEl.textContent = selectedIds.size;
    updateSelectAllButton();

    // 清理按钮
    const cleanBtn = document.getElementById('btnClean');
    if (cleanBtn) cleanBtn.disabled = selectedIds.size === 0 || isScanning || isCleaning;

    // 顶层分组汇总（条目数量 + 总占用大小，兼容扁平分组）
    // P2：计数与已选数量按当前筛选口径展示（无筛选时与原口径一致）；
    // 已选大小汇总仍以 selectedIds 为准，不随筛选改变。
    for (const [groupKey, group] of Object.entries(CATEGORIES)) {
      let items;
      let catCount = 0;
      if (group.subGroups) {
        items = [];
        for (const sg of group.subGroups) {
          const matched = visibleItems(sg.items);
          if (matched.length > 0) catCount++;
          items.push(...matched);
        }
      } else {
        items = visibleItems(group.items || []);
      }
      const groupSize = groupTotalSize(items);
      const countEl = document.querySelector(`[data-group-count="${groupKey}"]`);
      if (!countEl) continue;
      const totalItems = items.length;
      const selectedCount = items.filter(i => selectedIds.has(i.id)).length;
      const sizePart = groupSize > 0 ? ` · ${formatSize(groupSize)}` : '';
      if (group.subGroups) {
        countEl.textContent = `${totalItems} 项 · ${catCount} 分类${selectedCount > 0 ? ` · ${selectedCount}/${totalItems} 已选` : ''}${sizePart}`;
      } else {
        countEl.textContent = `${totalItems} 项${selectedCount > 0 ? ` · ${selectedCount}/${totalItems} 已选` : ''}${sizePart}`;
      }
    }
  }

  // 进度条
  function setProgress(percent, label) {
    const section = document.getElementById('progressSection');
    const fill = document.getElementById('progressFill');
    const valueEl = document.getElementById('progressValue');
    const labelEl = document.getElementById('progressLabel');
    if (section) section.style.display = 'block';
    if (section) section.setAttribute('aria-busy', percent < 100 ? 'true' : 'false');
    if (fill) fill.style.width = percent + '%';
    if (valueEl) valueEl.textContent = Math.round(percent) + '%';
    if (labelEl && label) labelEl.textContent = label;
  }

  function hideProgress() {
    const section = document.getElementById('progressSection');
    if (section) {
      section.style.display = 'none';
      section.setAttribute('aria-busy', 'false');
    }
  }

  // ==================== P1-12：扫描进度流式化 ====================
  // 主进程逐项推送 cleanup:scan-progress；此处真实更新进度条（0-90% 按项数折算）
  // 并就地更新对应行的 大小/路径 单元格，避免整表重渲染。
  let streamThrottleRaf = 0;
  let streamTotals = new Map(); // groupKey -> 已流式回传的 size 合计（供分组汇总）

  // 条目 id -> 顶层分组 key（getItemById 返回的 group 是标题，不能直接用于 data-group-count）
  function groupKeyForItem(id) {
    // 索引命中 + **调用侧**补可见性判定：旧实现走 getGroupItems()（已按 hiddenIds 过滤），
    // 因此 detect 未命中（隐藏）的条目算不出分组 ⇒ 不计入 streamTotals / 分组汇总。
    // 这条口径必须原样保住，所以 hiddenIds 不进索引（见 rebuildItemIndex 的铁律注释）。
    const hit = itemIndex.get(id);
    if (!hit) return null;
    return hiddenIds.has(id) ? null : hit.groupKey;
  }

  function onScanProgress(payload) {
    if (!isScanning || !payload || !payload.item) return;
    const r = payload.item;
    // FC-4（2026-09-15）：fileclean 扫描期间主进程推送 id 前缀 `__fileclean:` 的占位进度项，
    // 只更新进度条（不写入 scanResults/streamTotals、不触发行/分组渲染），扫描完成后由
    // fileclean.scan 的返回结果统一落真实数据。
    const isSentinel = typeof r.id === 'string' && r.id.startsWith('__fileclean:');
    if (isSentinel) {
      const pct0 = payload.total > 0 ? Math.min(90, (payload.done / payload.total) * 90) : 0;
      setProgress(pct0, `扫描中... ${Math.floor(payload.done)}/${payload.total} 项 · ${Math.round(pct0)}%`);
      return;
    }
    scanResults.set(r.id, r);
    if (r.size > 0) {
      const gk = groupKeyForItem(r.id);
      if (gk) streamTotals.set(gk, sizeNumber(streamTotals.get(gk)) + sizeNumber(r.size));
    }
    const pct = payload.total > 0 ? Math.min(90, Math.round((payload.done / payload.total) * 90)) : 0;
    setProgress(pct, `扫描中... ${payload.done}/${payload.total} 项 · ${Math.round(pct)}%`);
    if (!streamThrottleRaf) {
      streamThrottleRaf = requestAnimationFrame(() => {
        streamThrottleRaf = 0;
        patchRow(r);
        updateGroupSummary(r);
      });
    }
  }

  // 就地更新单行的 size / path 单元格（行不存在或已重渲染则跳过，最终统一重渲染兜底）
  function patchRow(r) {
    const row = document.querySelector(`#categoryList .xtable-row[data-id="${CSS.escape(r.id)}"]`);
    if (!row) return;
    const sizeCell = row.querySelector('[data-cell="size"]');
    if (sizeCell) sizeCell.innerHTML = (r.size !== null && r.size !== undefined) ? formatSize(r.size) : '<span class="xtable-cell-muted">—</span>';
    const pathCell = row.querySelector('[data-cell="path"]');
    if (pathCell && r.path) {
      const autoTag = r.pathSource === 'auto' ? ' <span class="path-auto-tag">自动定位</span>' : '';
      const fileTag = r.fileCount > 0 ? ` <span class="path-auto-tag">共 ${r.fileCount} 个文件</span>` : '';
      const regTag = r.regCount > 0 ? ` <span class="path-auto-tag">注册表 ${r.regCount} 项</span>` : '';
      const blockedTag = Array.isArray(r.blockedBy) && r.blockedBy.length
        ? ` <span class="path-blocked-tag" data-tip="执行前会跳过此项目并提示原因">需关闭: ${escapeHtml(r.blockedBy.join(', '))}</span>` : '';
      // R1-2：见上方同名标签的说明（流式阶段与全量渲染必须同口径，
      // 否则行会在流式更新到最终值时把标签丢掉）
      const reparseTag = Number(r.skippedReparse) > 0
        ? ` <span class="path-auto-tag" data-tip="扫描时跳过了 ${escapeHtml(String(r.skippedReparse))} 个联接点/挂载点目录（它们指向别的子树，深入会重复计数）">已跳过 ${escapeHtml(String(r.skippedReparse))} 个联接点</span>` : '';
      // A1-M02：与全量渲染同口径（流式补丁不得把「不可读」标签丢掉）
      const unreadableTag = Number(r.skippedUnreadable) > 0
        ? ` <span class="path-auto-tag" data-tip="扫描时有 ${escapeHtml(String(r.skippedUnreadable))} 个目录读不到（权限或 IO 失败），候选清单可能不完整">${escapeHtml(String(r.skippedUnreadable))} 个目录不可读</span>` : '';
      // 2026-10-04 审计 §4.3：同口径的截断标签（流式/补丁路径）
      const truncTag = r.filesTruncated
        ? ' <span class="path-auto-tag" data-tip="文件清单超出单次上限被截断，实际清理范围可能大于所列">清单已截断</span>' : '';
      pathCell.innerHTML = `<span class="xtable-cell-text xtable-cell-path" data-tip="${escapeHtml(r.path)}">${escapeHtml(xtable.middleEllipsis(r.path, 72))}${autoTag}${fileTag}${regTag}${reparseTag}${unreadableTag}${truncTag}${blockedTag}</span>`;
    }
  }

  // 流式阶段仅更新分组计数条中的大小部分，避免整表重渲染
  function updateGroupSummary(r) {
    const gk = groupKeyForItem(r.id);
    if (!gk) return;
    const countEl = document.querySelector(`[data-group-count="${gk}"]`);
    if (!countEl) return;
    const group = CATEGORIES[gk];
    if (!group) return;
    const items = getGroupItems(group);
    const totalItems = items.length;
    const selectedCount = items.filter(i => selectedIds.has(i.id)).length;
    const size = streamTotals.get(gk) || 0;
    const sizePart = size > 0 ? ` · ${formatSize(size)}` : '';
    if (group.subGroups) {
      countEl.textContent = `${totalItems} 项 · ${group.subGroups.length} 分类${selectedCount > 0 ? ` · ${selectedCount}/${totalItems} 已选` : ''}${sizePart}`;
    } else {
      countEl.textContent = `${totalItems} 项${selectedCount > 0 ? ` · ${selectedCount}/${totalItems} 已选` : ''}${sizePart}`;
    }
  }

  // 扫描
  // 2026-10-07 用户裁定：扫描范围 = 当前勾选项（一项未勾 = 全量）。「全选」与全量等价；
  // 「只勾一项」就只扫那项 —— 与「开始清理」只看勾选的执行范围口径对齐。
  async function scan() {
    if (isScanning) return;
    isScanning = true;
    const isFullScan = selectedIds.size === 0;
    const scopeIds = isFullScan ? ALL_IDS.slice() : ALL_IDS.filter(id => selectedIds.has(id));
    if (isFullScan) {
      scanResults.clear();
      fileCleanData.clear();
    } else {
      // 子集扫描只刷新本次范围：其余条目保留上次结果、勾选不动（扫描不替用户做选择）
      for (const id of scopeIds) {
        scanResults.delete(id);
        fileCleanData.delete(id);
      }
    }
    updateUI();

    setProgress(0, '正在准备扫描...');
    const btnScan = document.getElementById('btnScan');
    if (btnScan) btnScan.disabled = true;

    streamTotals.clear();
    // Electron 模式：进度由 cleanup:scan-progress 逐项真实推送（P1-12）。
    // 预览/旧 preload 无该事件时，退回模拟进度。
    const streaming = !!(window.api?.cleanup?.onScanProgress);
    let progress = 0;
    let progressTimer = null;
    if (!streaming) {
      progressTimer = setInterval(() => {
        if (isScanning && progress < 90) {
          progress += 5;
          setProgress(progress, `扫描中... ${Math.round(progress)}%`);
        }
      }, 200);
    }

    try {
      let results = [];
      if (window.api?.cleanup) {
        // Electron 模式：调用 PowerShell（排除文件清理项）
        const regularIds = scopeIds.filter(id => !FILECLEAN_IDS.includes(id));
        // partial：后端保快照桶并合并（只覆盖本次命中的 id）；全量沿用清桶重建
        const resp = await window.api.cleanup.scan(regularIds, !isFullScan);
        if (!resp.success) {
          throw new Error(resp.message || '扫描失败');
        }
        results = resp.data;

        // 文件清理项独立扫描（FC-4：传 total/doneBase 让主进程与常规条目共用同一进度条；
        // total = 常规则数 + fileclean 项数，与本次扫描范围口径一致）
        const pathConfig = window.pathbinding?.getConfig?.() || {};
        const fcScope = FILECLEAN_IDS.filter(id => scopeIds.includes(id));
        const scanTotal = regularIds.length + fcScope.length;
        let fcDoneBase = regularIds.length;
        for (const id of fcScope) {
          const item = getItemById(id);
          if (!item || !item.fileCleanType) continue;
          const customPath = item.fileCleanType === 'qq' ? pathConfig.qqFileDir : pathConfig.wechatFileDir;
          try {
            const fcResp = await window.api.fileclean.scan(item.fileCleanType, customPath);
            if (fcResp.success && fcResp.data) {
              fileCleanData.set(id, fcResp.data);
              // v4 P2-E（R1-M05）：扫描达上限要留痕（旧实现无 truncated 字段，用户以为扫完了）
              if (fcResp.data.truncated) {
                console.warn(`[Trim] ${item.name} 扫描达上限，结果可能不完整`);
                window.app?.toast?.('warning', `${item.name} 目录较大，扫描已达上限，结果可能不完整`);
              }
              results.push({
                id,
                name: item.name,
                path: fcResp.data.scanPath,
                pathSource: 'configured',
                size: fcResp.data.totalSize,
                risk: 'low',
                exists: true
              });
            } else {
              // v4 P2-E（R1-M05）：扫描失败不得伪装成「未配置」（旧实现 message 从未被读）——
              // 有配置但扫不动时如实展示原因，用户才能区分「没配」与「查不到」。
              const why = (fcResp && fcResp.message) || '未知原因';
              console.warn(`[Trim] 文件清理扫描失败（${item.name}）: ${why}`);
              results.push({
                id,
                name: item.name,
                path: customPath ? `扫描失败：${why}` : '未配置',
                pathSource: 'configured',
                size: 0,
                risk: 'low',
                exists: false
              });
            }
          } catch (e) {
            console.warn(`[Trim] 文件清理扫描异常（${item.name}）: ${e.message}`);
            results.push({
              id,
              name: item.name,
              path: customPath ? `扫描失败：${e.message}` : '未配置',
              pathSource: 'configured',
              size: 0,
              risk: 'low',
              exists: false
            });
          }
          // FC-4：本条目扫完，进度基准前移一位，供下一个 fileclean 条目使用
          fcDoneBase++;
        }
      } else {
        // 浏览器预览模式：使用模拟数据
        await new Promise(r => setTimeout(r, 1500));
        results = ALL_IDS.map(id => ({
          id,
          name: getItemById(id)?.name || id,
          path: MOCK_PATHS[id] || `C:\\Windows\\...\\${id}`,
          pathSource: MOCK_PATHS[id] ? 'configured' : 'configured',
          size: MOCK_SIZES[id] || Math.floor(Math.random() * 500) * 1024 * 1024,
          // 审查 7-1：fail-safe——条目在规则表查不到时按高危处理（触发红色二次确认），禁止静默降级为低危
          risk: getItemById(id)?.risk || 'high',
          exists: true
        }));
        // 模拟文件清理数据
        for (const id of FILECLEAN_IDS) {
          const mockFiles = [];
          for (let i = 0; i < 15; i++) {
            mockFiles.push({
              path: `C:\\mock\\${id}\\image_${i}.jpg`,
              name: `image_${i}.jpg`,
              size: Math.floor(Math.random() * 5000000),
              category: 'image',
              ext: '.jpg',
              mtime: new Date().toISOString()
            });
          }
          fileCleanData.set(id, {
            files: mockFiles,
            totalSize: MOCK_SIZES[id] || 0,
            scanPath: MOCK_PATHS[id] || 'C:\\mock'
          });
        }
      }

      // G-4：回收站条目的「占用大小」由 Shell API 现查覆盖。
      // 扫描引擎对它只发一条 size=0 的占位行（native-scanner 的 emit_recycle_bin），
      // 真实条目数/体积只有 SHQueryRecycleBinW 能回答。查询失败**不编数字**：
      // 条目保持 size 0 且仍然可见，用户点清理时会拿到失败原因。
      // 注：条目不存在时这里补一条——它必须始终可见（入口不能因「扫描不产路径」消失）。
      // G-4 追补：回收站数字仅在本轮范围含它（或全量）时现查覆盖；子集扫描不含它时
      // 完全不动（不补条目、不查、不覆盖），「只扫勾选项」的口径才自洽。
      if ((isFullScan || scopeIds.includes(RECYCLE_ID)) && window.api?.cleanup?.recycleStats) {
        let recycle = results.find(r => r.id === RECYCLE_ID);
        if (!recycle) {
          const meta = getItemById(RECYCLE_ID);
          if (meta) {
            recycle = { id: RECYCLE_ID, name: meta.name, path: '', pathSource: 'shell', size: 0, risk: meta.risk, exists: true };
            results.push(recycle);
          }
        }
        if (recycle) {
          try {
            const st = await window.api.cleanup.recycleStats();
            if (st && st.success) {
              recycle.size = sizeNumber(st.bytes);
              recycle.recycleCount = Number(st.count) || 0;
            } else {
              recycle.recycleStatsError = (st && st.message) || '查询回收站失败';
            }
          } catch (e) {
            recycle.recycleStatsError = e.message || String(e);
          }
        }
      }

      // P1：detect 未命中的条目不会出现在扫描结果中——标记为隐藏（重新扫描/换规则后恢复）。
      // 子集扫描只更新本次点名的 id：命中即恢复显示，未命中即隐藏（其余条目保持原状）。
      const gotIds = new Set(results.map(r => r.id));
      if (isFullScan) {
        hiddenIds.clear();
        for (const id of ALL_IDS) {
          if (!FILECLEAN_IDS.includes(id) && !gotIds.has(id)) hiddenIds.add(id);
        }
      } else {
        for (const id of scopeIds) {
          if (gotIds.has(id)) {
            hiddenIds.delete(id);
          } else {
            hiddenIds.add(id);
            selectedIds.delete(id); // 本机已无此内容的条目不该继续留在勾选里
          }
        }
      }
      for (const r of results) {
        scanResults.set(r.id, r);
      }
      // 应用缓存可能被安装到其他位置。自动发现只作为候选，必须由用户确认后才采用。
      const relocations = results.filter(r => r.pathSource === 'auto' && r.autoPath && r.autoPath !== r.configuredPath);
      for (const result of relocations) {
        const useAutoPath = await window.app?.confirm(
          `${result.name}发现其他目录`,
          `检测到可用缓存目录：\n${result.autoPath}\n\n原配置路径：\n${result.configuredPath || result.path}\n\n是否使用自动发现的目录进行本次扫描和清理？`,
          '使用此目录'
        );
        if (!useAutoPath) {
          result.path = result.configuredPath || result.path;
          result.pathSource = 'configured';
          result.exists = false;
          result.size = 0;
        }
        scanResults.set(result.id, result);
      }
      setProgress(100, '扫描完成');
      // 默认勾选所有安全项（**仅无勾选的全量扫描**——子集扫描不替用户改勾选）
      // v3.2.1 类目重构：维护与特殊操作域（special，DISM/回收站/Installer 缓存）为不可逆
      // 系统动作，永不默认勾选（文档 §2.2 域 5 / P4）
      if (isFullScan) {
        for (const r of results) {
          const meta = getItemById(r.id);
          if (meta && meta.domain === 'special') continue;
          if (r.risk === 'low' && r.size > 0) selectedIds.add(r.id);
        }
      }
      await new Promise(r => setTimeout(r, 400));
      hideProgress();
      // 重新渲染带 size
      renderCategoryList();
      updateUI();
      const total = dedupSize(Array.from(scanResults.keys()));
      window.app?.toast('success', isFullScan
        ? `扫描完成，共发现 ${formatSize(total)} 可清理空间`
        : `扫描完成，已刷新所选 ${scopeIds.length} 项`);
    } catch (e) {
      hideProgress();
      window.app?.toast('error', '扫描失败: ' + e.message);
      maybeOfferElevation('扫描失败，可能需要管理员权限才能访问部分系统目录。');
    } finally {
      isScanning = false;
      if (btnScan) btnScan.disabled = false;
      // 复位标志后必须再刷一次按钮态：try 尾部那次 updateUI 跑在 isScanning 仍为 true 时，
      // 而 #btnClean 的禁用判据里带着这个标志 ⇒ 扫描完成后「开始清理」一直停在禁用，
      // 用户要再动一次勾选才点得动（2026-10-22 真机 CDP 实测，扫完 8 分钟仍 disabled=true）。
      updateUI();
      // 审查 L14：模拟进度的定时器要在 finally 里关掉。Tauri 下 streaming 恒真、这段不执行，
      // 但它是「扫完还在跑的 200ms 定时器」这种泄漏的现成形状，别留给下一次。
      if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
    }
  }

  function setCleaningBtn(cleaning) {
    const btn = document.getElementById('btnClean');
    if (!btn) return;
    btn.classList.toggle('busy', cleaning);
    const label = btn.querySelector('span');
    if (label) label.textContent = cleaning ? '清理中...' : '开始清理';
  }

  // clean() 的每一条出口都必须做同一组复位（互斥标志 / 按钮态 / 计数与禁用态）。
  // F4a1-M02 的病灶就在这里：置位与复位靠逐个 return 记忆，中风险早退漏了一条
  // setCleaningBtn(false) ⇒ 用户点「取消」后按钮仍是「清理中...」，而 #btnClean 是
  // .btn-accent（main.css 的 .busy 规则就挂在这个档位上）⇒ 图标一直转、文案与实情相反。
  // 收成唯一出口后，新增早退只需想「return 前调 finishClean()」。
  function finishClean() {
    isCleaning = false;
    setCleaningBtn(false);
    updateUI();
  }

  // v3.3.4：清理前占用检测弹窗。返回：
  //   null            —— 无占用/检测不可用/无计划清单，调用方照常清理
  //   'cancel'        —— 用户关闭弹窗（×/ESC/背景），放弃本次清理
  //   'kill'          —— 用户选择「立即结束进程」，占用进程已结束，照常清理全部
  //   { skipIds }     —— 用户选择「不结束并放弃清理它们」，返回应跳过的条目 id 集合
  //   'aborted'       —— 确认件（modal.js）缺席：独立信号，fail-closed 中止本次清理
  //                      （2026-10-15 裁定 / 方案 J4；刻意不复用 null——null 的既有语义是
  //                      「照常清理」，混用会静默丢掉占用告知与「放弃清理它们」的选择权）
  async function offerCloseLocked(ids) {
    if (!ids.length || !window.api?.cleanup?.checkLocked) return null;
    let info = null;
    try {
      const resp = await window.api.cleanup.checkLocked(ids);
      if (!resp || !resp.success) return null; // 检测不可用不阻塞清理（执行侧仍会如实报残留）
      info = resp;
    } catch (e) {
      return null;
    }
    const procs = Array.isArray(info.procs) ? info.procs : [];
    // P1-6C：后端现在把畸形 `@@LOCKED@@` 行数随回执带下来（`malformed`/`partial`）。
    // 不消费它的话，「协议被打断、一条都没解析出来」与「确实没有文件被占用」在界面上
    // 仍然同形，用户会当成可以安全清理。占用告知是咨询性的，因此**只提示不拦**：
    // 真被占用时执行侧仍会逐条如实报失败（与 R4 的失败分档同口径）。
    const partialNote = Number(info.malformed) > 0
      ? `占用检测有 ${info.malformed} 条输出畸形已跳过，下方列表可能不完整。` : '';
    if (!procs.length) {
      if (partialNote) window.app?.toast?.('warning', partialNote);
      return null; // 无占用（但协议异常要单独说一声）
    }
    // 可结束进程（非系统关键）；critical 进程只展示不提供结束入口
    const killable = procs.filter(p => !p.critical);
    const critical = procs.filter(p => p.critical);
    if (!killable.length && !critical.length) return null;
    const skipIds = new Set(Object.keys(info.lockedByItem || {}));
    if (!window.modal?.create) {
      // fail-closed（2026-10-15 裁定 / 方案 J4）：组件缺席时中止而非照常清理。代价：modal.js
      // 真缺席时常规清理链整批不可用——那本就是不该发生的状态（index.html 恒挂 modal.js），
      // 而「照常清理」会把占用告知与用户的处置选择权一起吞掉。
      window.app?.toast?.('error', '确认组件未加载，本次清理已中止');
      return 'aborted';
    }

    return new Promise(resolve => {
      let settled = false;
      const finish = v => { if (!settled) { settled = true; resolve(v); } };
      const appCount = Object.entries(info.byApp || {}).sort((a, b) => b[1] - a[1]);
      const listRows = appCount.map(([app, cnt]) =>
        `<div class="lock-app-row"><span class="lock-app-name" data-tip="${escapeHtml(app)}">${escapeHtml(app)}</span><span class="lock-app-count">${cnt} 个文件</span></div>`
      ).join('');
      const criticalNote = critical.length
        ? `<div class="lock-critical-note">另有系统关键进程占用（${critical.map(p => escapeHtml(p.app)).join('、')}），不提供结束入口，将被跳过。</div>`
        : '';
      const ctrl = window.modal.create({
        id: 'lockModal-' + Date.now(),
        title: '部分文件正在被使用',
        bodyHtml: `
          <div class="confirm-message">以下应用正在使用要清理的文件，目前无法清理，您可以关闭它们以正常清理。</div>
          <div class="lock-app-list">${listRows}</div>
          ${criticalNote}${partialNote ? `<div class="lock-critical-note">${escapeHtml(partialNote)}</div>` : ''}`,
        footerHtml: `
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary" data-lock="skip" type="button">不结束并放弃清理它们</button>
          <button class="btn btn-primary" data-lock="kill" type="button">立即结束进程</button>`,
        onClose() { finish('cancel'); }
      });
      const killBtn = ctrl.footer.querySelector('[data-lock="kill"]');
      const skipBtn = ctrl.footer.querySelector('[data-lock="skip"]');
      if (!killable.length) {
        // 全部为系统关键进程：不提供结束入口，只允许放弃这些条目
        killBtn.disabled = true;
        killBtn.setAttribute('data-tip', '占用进程为系统关键进程，不支持结束');
      }
      killBtn.addEventListener('click', async () => {
        killBtn.disabled = true;
        killBtn.textContent = '正在结束...';
        try {
          await window.api.cleanup.killLockedProcesses();
        } catch (e) { /* 结束失败仍继续，执行侧会如实报残留 */ }
        // 进程退出到句柄释放有短暂延迟，等一拍再进入清理
        await new Promise(r => setTimeout(r, 1200));
        finish('kill');
        ctrl.close();
      });
      skipBtn.addEventListener('click', () => {
        finish({ skipIds });
        ctrl.close();
      });
    });
  }

  // ==================== C1-1：占用查询（主窗内嵌卡片，2026-10-16） ====================
  // 给用户一个「拿一个文件/目录来问谁占着我」的入口（对齐清浊 UnlockFilePage 的功能定位，
  // 形态拍板走主窗内嵌页签）。与清理前占用检测（offerCloseLocked）的关系：后端同一条 RM
  // 管线（checklocked_json + parse_locked_lines），写同一份按窗一次性 PID 白名单。
  // 清浊四坑对应（实现侧逐条注释见 scan_execute.rs `cleanup_query_locked`）：
  // ① 目录整树由后端收集（上限截断如实标注）；② RM 会话句柄生命周期不跨函数（Rust RAII）；
  // ③ 检测（查询，只读）与结束（一次性白名单）两步式不合并；④ 承载于现成分段视图，不新开窗。
  // 结束进程不可逆：走 confirmDanger 确认（焦点落主按钮），系统关键进程只展示、无结束入口。
  let lockQueryBusy = false;
  let lockQueryPath = '';       // 最近一次成功查询的路径（后端展开后的实际值；结束进程后重查用）
  let lockQueryProcs = [];      // 最近一次结果的进程清单（结束按钮的可用性与确认文案都读它）

  function renderLockQueryResult(resp) {
    const box = document.getElementById('lockQueryResult');
    const killBtn = document.getElementById('lockKillBtn');
    const killText = document.getElementById('lockKillBtnText');
    if (!box) return;
    const procs = Array.isArray(resp.procs) ? resp.procs : [];
    const killable = procs.filter(p => p && !p.critical);
    lockQueryPath = typeof resp.path === 'string' ? resp.path : '';
    lockQueryProcs = procs;
    if (killBtn) killBtn.disabled = killable.length === 0;
    if (killText) killText.textContent = killable.length ? `结束进程（${killable.length}）` : '结束进程';
    const scanned = Number(resp.scanned) || 0;
    const truncNote = resp.truncated ? '；目录文件数超过 2 万上限，结果已截断' : '';
    if (!procs.length) {
      box.innerHTML = `<div class="empty-state"><p>没有发现占用${scanned > 0 ? `（已检查 ${scanned} 个文件${truncNote}）` : '（目录内没有可查询的文件）'}。</p></div>`;
      return;
    }
    // 进程行复用清理前占用检测弹窗的既有样式（lock-app-*，零新增视觉 token）
    const rows = procs.map(p => {
      const name = String((p && p.app) || '未知应用');
      const right = p && p.critical
        ? '<span class="lock-app-count" data-tip="系统关键进程，不提供结束入口">系统关键 · 不可结束</span>'
        : `<span class="lock-app-count">PID ${Number(p && p.pid) || 0}</span>`;
      return `<div class="lock-app-row"><span class="lock-app-name" data-tip="${escapeHtml(name)}">${escapeHtml(name)}</span>${right}</div>`;
    }).join('');
    const criticalCount = procs.filter(p => p && p.critical).length;
    const note = criticalCount
      ? `<div class="lock-critical-note">${criticalCount} 个系统关键进程只展示、不提供结束入口，结束进程时会被跳过。</div>`
      : '';
    box.innerHTML = `<p class="opt-hint">共 ${procs.length} 个占用进程（已检查 ${scanned} 个文件${truncNote}）：</p>`
      + `<div class="lock-app-list">${rows}</div>${note}`;
  }

  async function runLockQuery(presetPath) {
    if (lockQueryBusy) return;
    const input = document.getElementById('lockQueryPath');
    const btn = document.getElementById('lockQueryBtn');
    const box = document.getElementById('lockQueryResult');
    if (!box) return;
    const path = String(typeof presetPath === 'string' ? presetPath : (input ? input.value : '') || '').trim();
    if (!path) {
      window.app?.toast?.('warning', '请先输入要查询的文件或目录路径');
      if (input && input.focus) input.focus();
      return;
    }
    if (!window.api?.cleanup?.queryLocked) {
      window.app?.toast?.('error', '占用查询不可用（适配层未加载）');
      return;
    }
    lockQueryBusy = true;
    // F4a1-L08：不给查询按钮挂 busy 类——唯一 .busy 规则挂在 .btn-accent.busy svg 上，
    // 该按钮是 btn-primary 加了无视觉表现；进行中反馈由 disabled 与结果区文案承担。
    if (btn) btn.disabled = true;
    // 查询期间先禁用「结束进程」：白名单每次查询覆盖，防在途查询改写名单后被误用
    const killBtn = document.getElementById('lockKillBtn');
    if (killBtn) killBtn.disabled = true;
    box.innerHTML = '<div class="empty-state"><p>正在查询占用…</p></div>';
    let resp = null;
    try {
      resp = await window.api.cleanup.queryLocked(path);
    } catch (e) {
      resp = null;
    }
    lockQueryBusy = false;
    if (btn) btn.disabled = false;
    if (!resp || !resp.success) {
      lockQueryPath = '';
      lockQueryProcs = [];
      if (killBtn) killBtn.disabled = true;
      const msg = (resp && resp.message) || '占用查询失败';
      window.app?.toast?.('error', msg);
      box.innerHTML = `<div class="empty-state"><p>${escapeHtml(msg)}</p></div>`;
      return;
    }
    renderLockQueryResult(resp);
  }

  async function killLockedFromQuery() {
    if (lockQueryBusy) return;
    const killable = lockQueryProcs.filter(p => p && !p.critical);
    if (!killable.length) return;
    if (!window.api?.cleanup?.killLockedProcesses) {
      window.app?.toast?.('error', '结束进程不可用（适配层未加载）');
      return;
    }
    // 不可逆操作：确认后再执行（与进程管理子窗同口径；焦点落主按钮由 confirmDanger 承担）
    const detail = killable.map(p => `• ${p.app}（PID ${p.pid}）`).join('\n');
    const ok = await window.app?.confirmDanger?.(
      '结束进程确认',
      `即将强制结束 ${killable.length} 个占用进程：\n${detail}\n\n未保存的数据可能丢失，是否继续？`,
      '结束进程',
      '取消',
      '进程结束后请重新查询，确认占用已解除。'
    );
    if (!ok) return;
    lockQueryBusy = true;
    const killBtn = document.getElementById('lockKillBtn');
    const killText = document.getElementById('lockKillBtnText');
    if (killBtn) killBtn.disabled = true;
    if (killText) killText.textContent = '正在结束…';
    let resp = null;
    try {
      resp = await window.api.cleanup.killLockedProcesses();
    } catch (e) {
      resp = null;
    }
    lockQueryBusy = false;
    const killed = resp && Array.isArray(resp.killed) ? resp.killed.length : 0;
    const failed = resp && Array.isArray(resp.failed) ? resp.failed.length : 0;
    if (resp && resp.success) {
      window.app?.toast?.(failed ? 'warning' : 'success', `已结束 ${killed} 个进程${failed ? `，${failed} 个未成功（可能已退出或缺权限）` : ''}`);
    } else {
      window.app?.toast?.('error', (resp && resp.message) || '结束进程失败');
    }
    // 等一拍让句柄释放后再重查（与清理前占用检测的 1200ms 同口径）
    await new Promise(r => setTimeout(r, 1200));
    if (lockQueryPath) await runLockQuery(lockQueryPath);
  }

  // 清理
  //
  // P1-7（F4a1-M12）：旧写法在 `isCleaning = true` 之后还连着四个 confirm/预查询 await，
  // 直到执行段才有 `try` —— 那一段里任何 reject 都跳过 `finally`，清理按钮永久点不动。
  // 现在拆两段：确认段自带 try/finally 且**不设 busy**，置 busy 后到 `try` 之间 await 数为 0。
  async function confirmCleanPlan() {
    // D10：risk 分级二次确认——高风险走红色 confirmDanger，中风险走黄色 confirmWarning。
    // 信任源统一为 $rule.risk（PS 侧门禁同源，见 cleanup-scripts.js），渲染层不做二次映射。
    // G-4：回收站**不参与这两档分级**——它是不可逆的批量动作，单独走下面那段
    // 「先现查条目数与体积、再红色确认」，避免同一件事被弹两次。
    const risky = Array.from(selectedIds)
      .map(id => scanResults.get(id))
      .filter(r => r && r.id !== RECYCLE_ID && (r.risk === 'high' || r.risk === 'medium'));
    const highRisk = risky.filter(r => r.risk === 'high');
    const mediumRisk = risky.filter(r => r.risk === 'medium');

    // F4a1-M01 的残留射程（2026-10-23 复核）：删除后果此前只出现在行 tooltip 上，
    // 而用户做决定那一刻看的是这枚确认弹窗——扫描回执结构上不带 ifDeleted（它是规则库
    // 字段，不经扫描通道），所以弹窗文案光靠 r.* 拼不出后果。改为按档位回查规则元数据，
    // 把后果**结构化**交给确认件渲染（默认展前 3 条，其余收进「展开其余 N 条后果」——
    // 全选时 22 条后果实测 1609px 对可视 659px，长墙等于没有）。没有登记 ifDeleted 的
    // 条目不进这个列表，不编话。
    const consequenceItems = (list) => list
      .map(r => { const m = getItemById(r.id); return m && m.ifDeleted ? { name: r.name, text: m.ifDeleted } : null; })
      .filter(Boolean);

    // 高风险二次确认（红色，删除类操作规范要求）。
    // 文案不再举例：现库清理域没有 high 档条目（high 只在优化面板用），这一支是给将来
    // 真升档时兜底的；旧文案点名的 Windows.old 不在库里、WinSxS 实为 medium，举例即误导。
    if (highRisk.length > 0) {
      const ok = await window.app?.confirmDanger(
        '高风险操作确认',
        `您选择了 ${highRisk.length} 个高风险项：\n${highRisk.map(r => '• ' + r.name).join('\n')}`,
        '确认清理',
        '取消',
        '删除后可能无法恢复，请确认已了解风险。',
        consequenceItems(highRisk)
      );
      if (!ok) return null;
    }

    // D10：中风险二次确认（黄色），与高风险红色确认分级
    if (mediumRisk.length > 0) {
      const ok = await window.app?.confirmWarning(
        '中风险操作确认',
        `您选择了 ${mediumRisk.length} 个中风险项（建议清理前核对用途）：\n${mediumRisk.map(r => '• ' + r.name).join('\n')}`,
        '确认清理',
        '取消',
        '部分中风险项可能被应用在使用，清理后若个别程序异常，可通过系统自带方式恢复。',
        consequenceItems(mediumRisk)
      );
      // F4a1-M02：取消支必须走调用方的收尾，本段不再自己复位 busy（busy 已移到确认之后才置起）
      if (!ok) return null;
    }

    // G-4：回收站的红色高危确认。方案 §2.2 G-4 的三条要求在这里兑现两条：
    //   ① 「先出条目数与体积」——**点击时现查一次**而不是用扫描时的数字：勾选到点
    //      「开始清理」之间回收站可能已被别的程序改动，拿旧数字做确认依据是骗人；
    //   ② 「走高危确认」——不可逆动作一律 confirmDanger（红色），不是中风险的黄色确认。
    // 空回收站直接摘掉勾选、不弹确认（没什么可清空的，弹窗只会训练用户无脑点确认）。
    if (selectedIds.has(RECYCLE_ID)) {
      const st = scanResults.get(RECYCLE_ID) || { name: '回收站' };
      let count = Number(st.recycleCount) || 0;
      let bytes = sizeNumber(st.size);
      try {
        const fresh = await window.api?.cleanup?.recycleStats?.();
        if (fresh && fresh.success) {
          count = Number(fresh.count) || 0;
          bytes = sizeNumber(fresh.bytes);
          st.recycleCount = count;
          st.size = bytes;
          scanResults.set(RECYCLE_ID, st);
        }
      } catch (_) {
        // 现查失败：沿用扫描时的数字（可能为 0）仍要确认——不能因为「查不到」就跳过提示
      }
      if (count === 0 && bytes === 0) {
        selectedIds.delete(RECYCLE_ID);
        window.app?.toast('info', '回收站已经是空的，已取消该项');
      } else {
        const ok = await window.app?.confirmDanger(
          '清空回收站确认',
          `将永久清空回收站中的 ${count} 个条目（约 ${formatSize(bytes)}）。\n清空后这些内容无法通过系统还原恢复。`,
          '清空回收站',
          '取消',
          '这是不可逆操作：清空回收站不经过 Trim 的删除备份，也没有回收站可再还原。'
        );
        if (!ok) return null;
      }
    }

    // 2026-10-04 审计 §4.3：确认清单与实际删除集来自两份数据——执行侧重新遍历
    // 目标，扫描后新增的文件、超出单次清单上限被截掉的行也会被清理，却从未出现在
    // 确认清单里。filesTruncated 此前标记了但渲染层零消费；清单被截断的条目必须在
    // 确认环节如实告知，让用户带着这个事实做决定（语义不变：差异可见而非绑定文件集）。
    const truncatedItems = Array.from(selectedIds)
      .map(id => scanResults.get(id))
      .filter(r => r && r.filesTruncated);
    if (truncatedItems.length > 0) {
      const ok = await window.app?.confirmWarning(
        '清理清单已截断确认',
        `所选 ${truncatedItems.length} 个条目的文件清单超出单次上限已截断：\n${truncatedItems.map(r => '• ' + r.name).join('\n')}\n实际清理范围可能大于上面列出的清单。`,
        '仍然执行',
        '取消',
        '清单截断意味着确认时看到的文件数少于将要清理的文件数；执行后请以日志与实测释放量为准。'
      );
      if (!ok) return null;
    }

    // v3.3.4：清理前占用检测——被占用的文件会清理失败，提前告知并给用户处置选择。
    // 只在常规清理项（有扫描计划清单）上做检测；文件清理项（FILECLEAN_IDS）不走此通道。
    // G-4：回收站也不走——占用检测按**文件路径**问「谁锁着它」，而清空回收站是
    // 系统级动作，没有「某个被锁的文件」可以指认，列进去只会给出一堆无关进程。
    const lockIds = Array.from(selectedIds).filter(id => scanResults.has(id) && !FILECLEAN_IDS.includes(id) && id !== RECYCLE_ID);
    let abandonIds = new Set();
    const lockDecision = await offerCloseLocked(lockIds);
    if (lockDecision === 'aborted') {
      // 确认件缺席（信号与提示都在 offerCloseLocked 内），与用户取消同姿势收尾
      return null;
    }
    if (lockDecision === 'cancel') return null;
    if (lockDecision && lockDecision.skipIds) abandonIds = lockDecision.skipIds;

    const allItems = Array.from(selectedIds)
      .filter(id => !abandonIds.has(id))
      .map(id => scanResults.get(id))
      .filter(Boolean);
    // 分离三类：常规清理项 / 文件清理项 / 回收站（G-4，唯一走 Shell API 的条目）
    const regularItems = allItems.filter(i => !FILECLEAN_IDS.includes(i.id) && i.id !== RECYCLE_ID);
    const fileCleanItems = allItems.filter(i => FILECLEAN_IDS.includes(i.id));
    const recycleItems = allItems.filter(i => i.id === RECYCLE_ID);
    // P2-06/D-02：记录本批「清了之后需要后置动作」的项——档位来自后端按目标路径机械判定
    // 注入的 postAction（cleanup-postactions.json + check-cleanup-postactions 重算核对）。
    // 执行回执不带该字段，所以在执行前从扫描缓存收集、完成后与成功项求交再提示。
    const explorerPickIds = new Set(
      allItems.filter(i => i.postAction === 'explorer').map(i => i.id)
    );
    // 回收站是单独的不可逆动作：只要它在场，force 就为真（沿用既有「有确认过就带 force」口径）
    const force = (highRisk.length > 0 || mediumRisk.length > 0 || recycleItems.length > 0);
    // 确认段到此为止：交出去的就是「用户已经逐档看过并同意的那份计划」。
    return { allItems, regularItems, fileCleanItems, recycleItems, force, explorerPickIds };
  }

  async function clean() {
    if (isCleaning || confirmInFlight || selectedIds.size === 0) return;
    confirmInFlight = true;
    let plan = null;
    try {
      plan = await confirmCleanPlan();
    } catch (e) {
      // 确认件自己挂了（modal IPC reject / 确认件缺失）：如实给一条出口，不再让按钮无声失灵
      window.app?.toast?.('error', '清理确认流程中断：' + ((e && e.message) || e));
    } finally {
      confirmInFlight = false;
    }
    if (!plan) return;
    const { allItems, regularItems, fileCleanItems, recycleItems, force, explorerPickIds } = plan;
    // P1-7：busy 一经置起，到下面执行段 `try` 之间**一个 await 都不许有**
    // （`tools/check-async-exits.mjs` 的 busy-window 判据钉的就是这条）。
    isCleaning = true;
    setCleaningBtn(true);
    updateUI();
    // v3.3.0（用户裁定）：执行选项 UI 已移除，固定语义——常规清理**不进回收站、直接永久删**。
    // 审查 v2-M20 订正：后半句原先写「回收站优先删除逻辑仍在主进程 trashOrUnlink 内」，那是
    // Electron 轨的事实；本轨（Tauri/Rust）没有 trashOrUnlink，`toRecycle=false` 使
    // `cleanup.rs` 的回收站支对该链不可达，永久删发生在 Rust 原生 cleanup_execute（原 PS 时代同名脚本已退役）里，**刻意不做
    // 永久删除兜底之外的补救**。红线口径已按这条裁定改写在 AGENTS §3（含"唯一例外"表述）。
    // 2026-10-04 审计 §5.5：force 是载荷兼容残留——「PS 闸」已随 S3 纯原生删除，
    // 主进程对 force 无任何判定语义（只进日志对账）。risk 确认弹窗的真实用途是
    // D10 分级告知；值照传只为不破坏 CHANNEL_MAP 载荷键。
    const toRecycle = false;
    const autoRebuild = true;
    setProgress(0, '开始清理...');

    let progress = 0;
    const progressTimer = setInterval(() => {
      if (isCleaning && progress < 90) {
        progress += 3;
        setProgress(progress, `清理中... ${progress}%`);
      }
    }, 200);

    // 2026-10-12：收到后端首个逐项进度事件即停掉上面的假进度计时器，此后进度条
    // 按真实项数推进（第 k/N 项 + 当前项名）。旧后端没有该事件时计时器照旧兜底。
    execProgressSink = function (p) {
      clearInterval(progressTimer);
      const total = Number(p && p.total) || 0;
      const done = Number(p && p.done) || 0;
      const pct = total > 0 ? Math.min(90, Math.round(5 + ((done - 1) / total) * 85)) : 10;
      const name = p && p.name ? ` · ${String(p.name).slice(0, 24)}` : '';
      // DISM 组件清理单条就要几分钟：进度条按项数折算会停在这一格不动，
      // 不提示会被当成卡死（2026-10-23 真机反馈）。按 id 判定，规则改名不失效。
      const hint = p && p.id === 'dismComponentCleanup' ? '（可能需要数分钟，请勿关闭）' : '';
      setProgress(pct, total > 0 ? `清理中... ${done}/${total} 项${name}${hint}` : '清理中...');
    };

    try {
      let result;

      if (window.api?.cleanup) {
        // 常规清理
        let regularResult = { totalFreed: 0, success: 0, failed: 0, skipped: 0, details: [] };
        if (regularItems.length > 0) {
          const resp = await window.api.cleanup.execute(regularItems, force, toRecycle, autoRebuild);
          // 审查 S5（2026-09-15）：主进程 success = 硬失败(error)为 0，partial 不计入。
          // 只要回传了 data 就必须读（否则部分成功/失败时整批统计与逐项明细被丢弃，
          // 与 finder:delete / fileclean:execute 的双通道协议对齐）；仅通道级失败才抛错。
          if (resp && resp.data) regularResult = resp.data;
          else if (!resp || !resp.success) throw new Error((resp && resp.message) || '清理失败');
        }

        // 文件清理
        let fcFreed = 0, fcSuccess = 0, fcFailed = 0;
        const fcDetails = [];
        for (const item of fileCleanItems) {
          const data = fileCleanData.get(item.id);
          if (data && data.files && data.files.length > 0) {
            const fcResp = await window.api.fileclean.execute(data.files);
            // 审查 FC-2/S5（2026-09-15）：原实现只判 success、无 else 分支，
            // 任一文件失败（被占用乃常态）就会把整批统计与逐项明细静默丢弃。
            // 改为始终读取 data 如实累加；通道级失败也落一条 error 明细，不再「消失」。
            if (fcResp && fcResp.data) {
              fcFreed += fcResp.data.totalFreed || 0;
              fcSuccess += fcResp.data.success || 0;
              fcFailed += fcResp.data.failed || 0;
              // K12（v6）：path 必须保留——「登记到重启后删除」的登记面只认逐文件
              // 失败明细（fileclean 回执的 details 逐文件带 path/status），旧映射把
              // path 丢掉，前端只能退回扫描数据全量顶替（= 把成功项也送去永久删）。
              fcDetails.push(...(fcResp.data.details || []).map(d => ({
                id: item.id,
                name: item.name,
                path: d.path || '',
                status: d.status,
                freed: d.freed,
                message: d.message || ''
              })));
            } else {
              fcFailed += data.files.length;
              fcDetails.push({
                id: item.id,
                name: item.name,
                status: 'error',
                freed: 0,
                message: (fcResp && fcResp.message) || '文件清理失败'
              });
            }
          }
        }

        // G-4：回收站清空（Shell API）。与常规/文件清理分开调用、结果并入同一份明细
        // —— 它**不是** cleanup:execute 的一条：那条链是「按快照文件集永久删」，
        // 对回收站既没有文件集也没有意义（见 backend 的 recycle_bin.rs 文件头）。
        let rcFreed = 0, rcSuccess = 0, rcFailed = 0;
        const rcDetails = [];
        for (const item of recycleItems) {
          const beforeBytes = sizeNumber(item.size);
          let detail;
          try {
            const rr = await window.api.cleanup.emptyRecycleBin();
            if (rr && rr.success) {
              // freed 取后端回执（清空前的系统口径体积）；后端没给就用扫描时数字兜底，
              // 但**不编**：两者都没有就是 0。
              const freed = Number(rr.freed) || beforeBytes || 0;
              // v4 P2-E（R4-M04）：count 后端查不到时回 null —— 此时不显示条目数，
              // 不得用 `|| 0` 把「没拿到」说成「0 个条目」。
              const countText = rr.count == null ? '' : `（${Number(rr.count) || 0} 个条目）`;
              detail = { id: RECYCLE_ID, name: item.name, status: 'ok', freed: freed, message: `已清空回收站${countText}` };
              rcFreed += freed;
              rcSuccess += 1;
            } else {
              detail = { id: RECYCLE_ID, name: item.name, status: 'error', freed: 0, message: (rr && rr.message) || '清空回收站失败' };
              rcFailed += 1;
            }
          } catch (e) {
            detail = { id: RECYCLE_ID, name: item.name, status: 'error', freed: 0, message: (e && e.message) || '清空回收站失败' };
            rcFailed += 1;
          }
          rcDetails.push(detail);
        }

        result = {
          totalFreed: (regularResult.totalFreed || 0) + fcFreed + rcFreed,
          success: (regularResult.success || 0) + fcSuccess + rcSuccess,
          failed: (regularResult.failed || 0) + fcFailed + rcFailed,
          // v3.3.4 文案纠偏：partial（部分成功，其余文件被占用）与 failed（硬失败）分开上报
          partial: regularResult.partial || 0,
          skipped: regularResult.skipped || 0,
          details: [...(regularResult.details || []), ...fcDetails, ...rcDetails]
        };
      } else {
        // 预览模式：模拟清理（汇总同样走 dedupSize —— 模拟回执也不该比真实可清量虚高，
        // 否则「预览看着对、真机数字两套」正是本仓反复钉的口径分叉）
        await new Promise(r => setTimeout(r, 2000));
        result = {
          totalFreed: dedupSize(allItems.map(i => i.id)),
          success: allItems.length,
          failed: 0,
          skipped: 0,
          details: allItems.map(i => ({
            id: i.id,
            name: i.name,
            status: 'ok',
            freed: i.size || 0,
            message: '已清理'
          }))
        };
      }

      setProgress(100, '清理完成');
      clearInterval(progressTimer);

      // 从结果中移除已清理的
      for (const d of result.details || []) {
        if (d.status === 'ok') {
          scanResults.delete(d.id);
          selectedIds.delete(d.id);
        }
      }

      // 上述命令并未真正执行；按审查结论 B6 删除该假日志，日志库只记录真实发生的操作。

      setTimeout(() => {
        hideProgress();
        renderCategoryList();
        updateUI();
        // K13：清理后刷新「重启后删除」入口——本批可能刚登记了失败项
        refreshPendingBadge();
        const freed = result.totalFreed || 0;
        // F4a1-L05：原「审查 M-3」分支读 result.recycledBytes/recycledCount——两字段
        // 在本文件只有读点、后端回执链零写点（v3.3.0 已固定 toRecycle=false），属死分支。
        let toastMsg = `清理完成！释放 ${formatSize(freed)} 空间`;
        // P2-06/D-02：本批含 explorer 后置动作且该项确有成功——在完成提示里声明
        // 「重启资源管理器后才重建」（图标/缩略图缓存由资源管理器持有，不重启会看到空白图标）。
        const explorerDone = (result.details || []).some(d => d.status === 'ok' && explorerPickIds.has(d.id));
        if (explorerDone) {
          toastMsg += '；图标与缩略图缓存将在重启资源管理器后重建';
        }
        window.app?.toast('success', toastMsg);
        // P3 残留复查提示 + 2026-10-13 失败引导：explorer 等进程占着句柄的文件在
        // 内核层就删不掉，光提示「关闭相关程序」是把难题丢回给用户（真机裁定：
        // 「每次都提示我结束 explorer，真结束了资源管理器不就没了吗」）。现在给
        // 两条可执行出路：① 重启资源管理器并重试（explorer 无损重启，几秒恢复）；
        // ② 登记到重启后删除（PendingFileRenameOperations，复用卸载域现成链）。
        // R4（2026-10-15）：失败按因分档后，重试面板只收「重试有意义」的项——
        // 删除时已不存在的（gone）与纯 skip 档（太新/排除/未解析/lossy）不再冒充
        // 「被占用」；权限不足（denied）保留（登记重启后删除对它仍有效）。
        const failedItems = (result.details || []).filter(d => {
          if (d.status === 'ok' && (Number(d.residual) || 0) === 0) return false;
          if (d.status === 'skip') return (Number(d.denied) || 0) > 0;
          return true;
        });
        if (failedItems.length > 0) {
          offerCleanupRetryPanel(failedItems, result.details || []);
          maybeOfferElevation(`${failedItems.length} 项未完全清理，部分文件可能需要管理员权限。`);
        } else if (result.partial > 0) {
          // v3.3.4 文案纠偏：部分成功不是失败——多数文件已清理，仅少数未删（占用或权限）
          window.app?.toast('warning', `${result.partial} 项部分清理完成（部分文件未删，可在下方引导中处理）`);
        }
      }, 600);
    } catch (e) {
      clearInterval(progressTimer);
      hideProgress();
      window.app?.toast('error', '清理失败: ' + e.message);
      maybeOfferElevation('清理操作失败，可能需要管理员权限。');
    } finally {
      execProgressSink = null;
      finishClean();
    }
  }

  // 无管理员权限时提供 UAC 提权入口（应用以 asInvoker 启动，按需提权）
  function maybeOfferElevation(reason) {
    try {
      const state = window.app?.getState?.();
      // isAdmin === false 表示已检测且非管理员；null 表示未检测完成
      if (state && state.isAdmin === false) {
        window.app?.requestElevation?.(reason);
      }
    } catch (_) { /* 提权提示失败不影响主流程 */ }
  }

  // 2026-10-12：回收站重试引导（原 offerTrashRetry）随回收站重试链整链退役——
  // 清理已固定全量永久删，「移入回收站失败」这一状态不再存在。

  // ==================== 图片预览（主窗内嵌 LiteBox） ====================
  // 旧「独立预览子窗」已退役（2026-10-13 用户裁定：去掉自写查看器、接入 LiteBox）。
  // 退役的直接动因是那个窗口的加载竞态：Rust 在 on_page_load(Finished) 里立即 emit
  // preview:data，而前端 listen 要经一次异步 IPC 才挂上，emit 几乎必然早于监听器就绪
  // ——事件丢失后 loadImage 永远不被调用，子窗停在 HTML 初始文案「正在加载图片…」。
  // 内嵌后数据不出窗口，竞态失去存在前提。
  //
  // 现实现：LiteBox（vendor/litebox.js，纯原生零依赖）+ asset 协议磁盘直连。
  // 图片不再整文件 base64 过 IPC；打开前先用 cleanup:allow-preview-assets 把**这一组**
  // 路径动态放行进 asset scope，暴露面不常开（详见 preview_assets.rs 模块注释）。
  let liteboxRange = null;

  function ensureLiteboxRange() {
    if (!liteboxRange || !document.body.contains(liteboxRange)) {
      liteboxRange = document.createElement('div');
      liteboxRange.id = 'liteboxRange';
      liteboxRange.style.display = 'none';
      document.body.appendChild(liteboxRange);
    }
    // 把 LiteBox 的点击监听从整个 document 收窄到本容器：主窗其它页有自己的
    // <img>（壁纸预览 bgThumb、应用图标回退等），不收窄会把它们也劫持成灯箱。
    // 每次调用都确认一遍收窄是否生效：本函数在 init() 就被调（装载序上 litebox.js 在前），
    // 但「容器已存在」不等于「range 已是本容器」——liteBox 晚于本脚本实例化时，
    // 只按容器存在就早退会把劫持窗口原样留下。
    if (window.liteBox?.setRange && window.liteBox.range !== liteboxRange) {
      window.liteBox.setRange(liteboxRange);
    }
    return liteboxRange;
  }

  // 删除按钮是**运行时注入**进灯箱控制条的——上游 LiteBox 没有删除概念，
  // 不改它的源码（vendored 文件除文件头登记的受控适配外与上游一致，便于同步）。
  function liteboxInjectDeleteButton() {
    const dialog = window.liteBox?.dialog;
    if (!dialog) return;
    // 2026-10-22 目检：左右箭头从「覆盖在图片上的浮层」收进**底部工具条**，
    // 顺序＝‹ › | + − ⟳ ⛶ | 删除 | 关闭。搬移节点保留上游绑定的事件监听；
    // 搬完把空的浮层行移除，避免留一条不可见但吃点击的区域。
    const nav = dialog.querySelector('.nav-controls');
    const prev = dialog.querySelector('#prev-btn');
    const next = dialog.querySelector('#next-btn');
    if (nav && prev && next) {
      const anchor = nav.querySelector('#zoom-in-btn') || null;
      nav.insertBefore(prev, anchor);
      nav.insertBefore(next, anchor);
      const overlay = dialog.querySelector('.lightbox-controls');
      if (overlay) overlay.remove();
    }
    if (dialog.querySelector('#liteboxDeleteBtn')) return;
    // 删除按钮必须挂到**底部工具条** `.nav-controls`，并在关闭按钮之前。
    // 2026-10-22 目检踩坑：挂进 `.lightbox-controls`（左右箭头那一行，space-between）时，
    // 按钮被推到图片右缘、压在看图内容上——那一行的第三子元素就是「最右」。
    const closeBtn = nav && nav.querySelector('#close-btn');
    if (!nav) return;
    const btn = document.createElement('button');
    btn.id = 'liteboxDeleteBtn';
    btn.type = 'button';
    btn.className = 'lb-action';
    btn.setAttribute('data-tip', '删除当前图片（进回收站）');
    // 图标+文字：可访问名由可见文字「删除」提供，另显式 aria-label 兜住读屏的缩写场景
    btn.setAttribute('aria-label', '删除当前图片（进回收站）');
    btn.innerHTML = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M5.5 5.5a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5z"/><path d="M2.5 1a1 1 0 0 0-1 1v1a1 1 0 0 0 1 1H3v9a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V4h.5a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v.5h-3V2a1 1 0 0 0-1-1h-3zm1 3h9v9a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4z"/></svg><span>删除</span>';
    btn.addEventListener('click', () => { liteboxDeleteCurrent(); });
    if (closeBtn) nav.insertBefore(btn, closeBtn);
    else nav.appendChild(btn);
  }

  // 灯箱当前显示图的原始路径：LiteBox 只存 URL，靠 data-src 反查容器里的源 img。
  function liteboxCurrentPath() {
    const img = window.liteBox?.getElem?.('.lightbox-image');
    const url = img && img.getAttribute('src');
    if (!url) return '';
    const hit = Array.from((liteboxRange || document).querySelectorAll('img[data-fullpath]'))
      .find(el => el.getAttribute('data-src') === url);
    return hit ? hit.getAttribute('data-fullpath') : '';
  }

  async function liteboxDeleteCurrent() {
    const filePath = liteboxCurrentPath();
    if (!filePath) {
      window.app?.toast('warning', '定位不到当前图片的原始路径，未执行删除');
      return;
    }
    const fileName = String(filePath).split('\\').pop() || filePath;
    // 删除类操作红色二次确认（与退役前的 preview-window.js 同文案同 danger 档）。
    // 2026-10-15 裁定（方案 J3）：整段自写 modal 分支 + 原生兜底删除，改走
    // window.app?.confirmDanger 位置参数——统一确认出口；app 缺席时表达式为 undefined
    // ⇒ 下面按未确认早退（fail-closed），且从此落进 check-confirm-danger.mjs 的形态扫描面。
    const confirmed = await window.app?.confirmDanger(
      '删除图片',
      `将删除「${fileName}」。\n文件将进入回收站，可在回收站还原。`,
      '删除',
      '取消',
      '删除后本页文件列表与容量统计将实时同步刷新。'
    );
    if (!confirmed) return;

    let resp = null;
    try {
      resp = await window.api.fileclean.deleteFile(filePath);
    } catch (e) {
      window.app?.toast('error', '删除失败：' + ((e && e.message) || e));
      return;
    }
    if (!resp || !resp.success) {
      // 后端已回 message（来源校验/不在扫描范围/回收站拒绝），照实说，不猜权限
      window.app?.toast('warning', '删除失败' + (resp && resp.message ? '：' + resp.message : ''));
      return;
    }

    // 同步本页数据（沿用原 initPreviewSync 的收缩口径）
    for (const [id, data] of fileCleanData.entries()) {
      if (!data || !Array.isArray(data.files)) continue;
      const idx = data.files.findIndex(f => f.path === filePath);
      if (idx !== -1) {
        const removed = data.files[idx];
        data.files.splice(idx, 1);
        data.totalSize = Math.max(0, (data.totalSize || 0) - (removed.size || 0));
        const sr = scanResults.get(id);
        if (sr) sr.size = Math.max(0, (sr.size || 0) - (removed.size || 0));
        break;
      }
    }
    renderCategoryList();
    updateUI();

    // 容器移除该图，跳到邻近一张；删空则关灯箱
    const before = Array.from(liteboxRange.querySelectorAll('img'));
    const idx = before.findIndex(el => el.getAttribute('data-fullpath') === filePath);
    if (idx >= 0) before[idx].remove();
    const rest = Array.from(liteboxRange.querySelectorAll('img'));
    if (rest.length) {
      const next = rest[Math.min(Math.max(idx, 0), rest.length - 1)];
      window.liteBox.click({ target: next });
    } else {
      window.liteBox.close();
    }
    window.app?.toast('success', '已删除（可在回收站还原）');
  }

  // ==================== 缩略图抽屉（2026-10-22 用户目检需求） ====================
  // 灯箱是 vendored 件：抽屉按删除按钮同一姿势在运行时注入，不改上游模板与布局逻辑，
  // 上游同步时只需重新确认计数器钩子还在。缩略图复用灯箱已算好的 asset URL
  // （range 里的 img[data-src]），不新开 IPC 通道、不新增命令。
  let liteboxDrawer = null;
  let liteboxDrawerIsOpen = false;
  let liteboxDrawerBound = false;
  let liteboxDrawerBatchId = null;
  let liteboxDrawerThumbObserver = null;
  let liteboxDrawerSrcObserver = null;
  let liteboxDrawerSuppressCancel = false;

  // 排序 + 按天分组是纯函数，离线自检按下面两个锚点整段抽取执行——判据不许只在
  // 窗口里成立。「时间未知」必须自成一档并排在最后，不许混进任何一天冒充已知时间。
  // #region groupImagesByDay
  function groupImagesByDay(files, nowMs) {
    const startOfDay = (ms) => {
      const d = new Date(ms);
      d.setHours(0, 0, 0, 0);
      return d.getTime();
    };
    const toMs = (v) => {
      if (typeof v === 'number') return v > 0 ? v : null;
      const s = String(v == null ? '' : v).trim();
      if (!s) return null;
      const n = Number(s);
      if (Number.isFinite(n)) return n > 0 ? n : null;
      const t = Date.parse(s);
      return Number.isFinite(t) && t > 0 ? t : null;
    };
    const now = Number.isFinite(nowMs) ? nowMs : Date.now();
    const today = startOfDay(now);
    const yesterdayDate = new Date(today);
    yesterdayDate.setDate(yesterdayDate.getDate() - 1);
    const yesterday = yesterdayDate.getTime();
    const dayLabel = (ms) => {
      if (ms === today) return '今天';
      if (ms === yesterday) return '昨天';
      const d = new Date(ms);
      const pad = (x) => String(x).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    };
    const known = [];
    const unknown = [];
    for (const f of files || []) {
      const t = toMs(f && f.mtime);
      if (t === null) unknown.push(f);
      else known.push({ file: f, t });
    }
    known.sort((a, b) => b.t - a.t);
    const groups = [];
    const byDay = new Map();
    for (const row of known) {
      const key = startOfDay(row.t);
      let g = byDay.get(key);
      if (!g) {
        g = { key, label: dayLabel(key), items: [] };
        byDay.set(key, g);
        groups.push(g);
      }
      g.items.push(row.file);
    }
    if (unknown.length) groups.push({ key: 'unknown', label: '时间未知', items: unknown });
    return groups;
  }
  // #endregion

  // 当前预览批次的文件（fileclean 扫描结果带 mtime，毫秒字符串；删除会同步收缩本数组）。
  function liteboxDrawerImageFiles() {
    const batch = liteboxDrawerBatchId ? fileCleanData.get(liteboxDrawerBatchId) : null;
    return batch && Array.isArray(batch.files) ? batch.files.filter(f => f.category === 'image') : [];
  }

  // path → range 源 img。URL 与点击目标都从这一张表取，避免再养一套 index 状态机。
  function liteboxDrawerSources() {
    const map = new Map();
    const range = ensureLiteboxRange();
    for (const img of range.querySelectorAll('img[data-fullpath]')) {
      const p = img.getAttribute('data-fullpath');
      if (p) map.set(p, img);
    }
    return map;
  }

  function liteboxDrawerCurrentSrc() {
    const img = window.liteBox?.getElem?.('.lightbox-image');
    return img ? (img.getAttribute('src') || '') : '';
  }

  // 当前图高亮跟着灯箱图片的 src 走：箭头/键盘翻页都能同步，不必改 LiteBox 的导航逻辑。
  function liteboxDrawerSyncCurrent() {
    if (!liteboxDrawer) return;
    const current = liteboxDrawerCurrentSrc();
    let active = null;
    for (const btn of liteboxDrawer.querySelectorAll('.lb-thumb')) {
      if (current && btn.getAttribute('data-src') === current) {
        btn.setAttribute('aria-current', 'true');
        active = btn;
      } else {
        btn.removeAttribute('aria-current');
      }
    }
    if (active) active.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  function liteboxDrawerRender() {
    if (!liteboxDrawer) return;
    const files = liteboxDrawerImageFiles();
    const sources = liteboxDrawerSources();
    const head = liteboxDrawer.querySelector('.lb-drawer-head');
    const body = liteboxDrawer.querySelector('.lb-drawer-body');
    if (!head || !body) return;
    head.textContent = `${files.length} 张 · 从新到旧`;
    const current = liteboxDrawerCurrentSrc();
    const esc = window.ds.esc;
    const escAttr = window.ds.escAttr;
    let html = '';
    for (const g of groupImagesByDay(files, Date.now())) {
      html += `<div class="lb-drawer-day" role="presentation">${esc(g.label)}</div>`;
      for (const f of g.items) {
        const source = sources.get(f.path);
        const url = source ? (source.getAttribute('data-src') || '') : '';
        const name = f.name || String(f.path || '').split('\\').pop() || '';
        const cur = current && url === current ? ' aria-current="true"' : '';
        html += `<button class="lb-thumb" type="button" role="option" tabindex="0"${cur} data-path="${escAttr(f.path)}" data-src="${escAttr(url)}" aria-label="${escAttr(name)}" data-tip="${escAttr(name)}"><img alt="" width="96" height="96" data-thumb-src="${escAttr(url)}"></button>`;
      }
    }
    if (!html) html = '<div class="lb-drawer-day" role="presentation">没有可预览的图片</div>';
    body.innerHTML = html;
  }

  // 懒加载：抽屉关闭即断开；根是抽屉滚动容器，滚到哪加载到哪（不再一次性请求整批图）。
  function liteboxDrawerWatchThumbs() {
    const body = liteboxDrawer?.querySelector('.lb-drawer-body');
    if (!body) return;
    liteboxDrawerThumbObserver?.disconnect();
    if (typeof IntersectionObserver !== 'function') {
      // 内核没有 IO 时退回一次性加载：宁可多请求，也不让抽屉空着。
      for (const img of body.querySelectorAll('img[data-thumb-src]')) {
        const url = img.getAttribute('data-thumb-src');
        if (url) img.src = url;
      }
      return;
    }
    liteboxDrawerThumbObserver = new IntersectionObserver((entries, obs) => {
      for (const en of entries) {
        if (!en.isIntersecting) continue;
        const img = en.target;
        const url = img.getAttribute('data-thumb-src');
        if (url && !img.getAttribute('src')) img.src = url;
        obs.unobserve(img);
      }
    }, { root: body, rootMargin: '200px 0px' });
    for (const img of body.querySelectorAll('img[data-thumb-src]')) liteboxDrawerThumbObserver.observe(img);
  }

  function liteboxDrawerWatchCurrent() {
    const img = window.liteBox?.getElem?.('.lightbox-image');
    if (!img) return;
    liteboxDrawerSrcObserver?.disconnect();
    liteboxDrawerSrcObserver = new MutationObserver(() => liteboxDrawerSyncCurrent());
    liteboxDrawerSrcObserver.observe(img, { attributes: true, attributeFilter: ['src'] });
    liteboxDrawerSyncCurrent();
  }

  function liteboxDrawerSetOpen(open) {
    const drawer = liteboxDrawerEnsure();
    if (!drawer || open === liteboxDrawerIsOpen) return;
    const counter = window.liteBox?.dialog?.querySelector('.counter');
    liteboxDrawerIsOpen = open;
    if (counter) {
      counter.setAttribute('aria-expanded', open ? 'true' : 'false');
      counter.setAttribute('data-tip', open ? '收起缩略图抽屉' : '展开缩略图抽屉');
    }
    if (open) {
      liteboxDrawerRender();
      drawer.classList.add('lb-open');
      liteboxDrawerWatchThumbs();
      liteboxDrawerWatchCurrent();
    } else {
      drawer.classList.remove('lb-open');
      liteboxDrawerThumbObserver?.disconnect();
      liteboxDrawerThumbObserver = null;
      liteboxDrawerSrcObserver?.disconnect();
      liteboxDrawerSrcObserver = null;
      // 焦点留在即将隐藏的抽屉里会丢焦点，交还给仍可见的计数器。
      if (drawer.contains(document.activeElement) && counter) counter.focus();
    }
  }

  function liteboxDrawerEnsure() {
    const dialog = window.liteBox?.dialog;
    if (!dialog) return null;
    if (liteboxDrawer && dialog.contains(liteboxDrawer)) return liteboxDrawer;
    liteboxDrawer = document.createElement('div');
    liteboxDrawer.className = 'lb-drawer';
    liteboxDrawer.id = 'liteboxDrawer';
    liteboxDrawer.setAttribute('role', 'listbox');
    liteboxDrawer.setAttribute('aria-label', '本批图片缩略图');
    liteboxDrawer.innerHTML = '<div class="lb-drawer-inner"><div class="lb-drawer-head"></div><div class="lb-drawer-body"></div></div>';
    dialog.appendChild(liteboxDrawer);

    liteboxDrawer.addEventListener('click', (e) => {
      const btn = e.target.closest ? e.target.closest('.lb-thumb') : null;
      if (!btn || !liteboxDrawer.contains(btn)) return;
      const path = btn.getAttribute('data-path') || '';
      const range = ensureLiteboxRange();
      const source = Array.from(range.querySelectorAll('img[data-fullpath]'))
        .find(el => el.getAttribute('data-fullpath') === path);
      if (!source) return;
      // 复用灯箱既有切图入口（与删除后的邻图跳转同一姿势），不自己改 currentIndex。
      window.liteBox.click({ target: source });
      liteboxDrawerSyncCurrent();
    });

    // 方向键在抽屉内移动焦点；Tab 仍按原生顺序走（280 项时不强迫用户敲 280 次 Tab）。
    liteboxDrawer.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      const items = Array.from(liteboxDrawer.querySelectorAll('.lb-thumb'));
      const at = items.indexOf(document.activeElement);
      if (at < 0) return;
      e.preventDefault();
      const step = e.key === 'ArrowDown' ? 1 : -1;
      const next = items[Math.max(0, Math.min(items.length - 1, at + step))];
      if (next) next.focus();
    });

    if (!liteboxDrawerBound) {
      liteboxDrawerBound = true;
      const counter = dialog.querySelector('.counter');
      if (counter) {
        counter.setAttribute('role', 'button');
        counter.setAttribute('tabindex', '0');
        counter.setAttribute('aria-label', '图片计数与缩略图抽屉');
        counter.setAttribute('aria-controls', 'liteboxDrawer');
        counter.setAttribute('aria-expanded', 'false');
        counter.setAttribute('data-tip', '展开缩略图抽屉');
        const toggle = () => liteboxDrawerSetOpen(!liteboxDrawerIsOpen);
        counter.addEventListener('click', toggle);
        counter.addEventListener('keydown', (e) => {
          if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
          e.preventDefault();
          toggle();
        });
      }
      // 抽屉打开时 Esc 先关抽屉：capture 抢在灯箱挂在 document 冒泡段的处理器之前；
      // 抽屉关闭时这里完全放行，Esc 仍按灯箱原语义关灯箱。
      document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape' || !liteboxDrawerIsOpen) return;
        e.preventDefault();
        e.stopPropagation();
        // 这一次 Esc 已经花在抽屉上：紧接着的 dialog cancel 也要拦掉，否则浏览器
        // 默认动作会把灯箱一起关掉。标志只活到当前任务结束（cancel 同步于默认动作）。
        liteboxDrawerSuppressCancel = true;
        setTimeout(() => { liteboxDrawerSuppressCancel = false; }, 0);
        liteboxDrawerSetOpen(false);
      }, true);
      // 抽屉外点击只关抽屉；点计数器归上面的 toggle 管，不能被这条重复触发。
      dialog.addEventListener('click', (e) => {
        if (!liteboxDrawerIsOpen) return;
        const counterEl = dialog.querySelector('.counter');
        if (liteboxDrawer.contains(e.target) || (counterEl && counterEl.contains(e.target))) return;
        liteboxDrawerSetOpen(false);
      });
      // 灯箱被任何路径关掉（Esc/背景/关闭钮）时抽屉必须跟着收，否则下次打开会带着
      // 上一批缩略图与 observer 复活。
      dialog.addEventListener('close', () => liteboxDrawerSetOpen(false));
      // 原生 dialog 的 Esc 关闭是浏览器默认动作，keydown 的 preventDefault 未必兜得住；
      // 抽屉开着时拦截 cancel，把这一次 Esc 留给抽屉，灯箱保持打开。
      dialog.addEventListener('cancel', (e) => {
        if (liteboxDrawerSuppressCancel) {
          liteboxDrawerSuppressCancel = false;
          e.preventDefault();
          return;
        }
        if (!liteboxDrawerIsOpen) return;
        e.preventDefault();
        liteboxDrawerSetOpen(false);
      });
    }
    return liteboxDrawer;
  }

  function openPreview(id) {
    const data = fileCleanData.get(id);
    if (!data || !data.files) return;
    const images = data.files.filter(f => f.category === 'image');
    if (images.length === 0) {
      window.app?.toast('info', '没有可预览的图片文件');
      return;
    }
    if (!window.liteBox) {
      window.app?.toast('warning', '图片灯箱组件未加载，无法预览');
      return;
    }
    (async () => {
      // ① 先放行 asset 读取（只放本次这组图；失败就不开灯箱，不能拿白图糊弄）
      try {
        const resp = await window.api.cleanup.allowPreviewAssets(images.map(f => f.path));
        if (!resp || !resp.success) {
          window.app?.toast('warning', '无法读取这些图片：' + ((resp && resp.message) || '未知原因'));
          return;
        }
      } catch (e) {
        window.app?.toast('error', '无法读取这些图片：' + ((e && e.message) || e));
        return;
      }
      // ② 组 range 容器：src 直接走 asset 协议（convertFileSrc），浏览器自己管解码与缓存
      const range = ensureLiteboxRange();
      range.textContent = '';
      for (const f of images) {
        const img = document.createElement('img');
        // v6-K16：pathToUrl 在 api **顶层**（paths 命名空间没有该成员——旧调用
        // `window.api.paths.pathToUrl(...)` 必抛 TypeError，灯箱整块不亮）；
        // typeof 守卫与 fontmanager/pathbinding 两个既有消费点同口径。
        const url = (window.api && typeof window.api.pathToUrl === 'function')
          ? window.api.pathToUrl(f.path)
          : '';
        img.setAttribute('data-src', url);
        img.setAttribute('data-fullpath', f.path);
        img.setAttribute('data-caption', `${f.name || ''} · ${formatSize(f.size)}`);
        img.alt = f.name || '图片';
        img.src = url;
        range.appendChild(img);
      }
      // ③ 注入删除按钮与缩略图抽屉钩子（抽屉默认收起），再打开第一张
      liteboxDrawerBatchId = id;
      liteboxInjectDeleteButton();
      liteboxDrawerEnsure();
      liteboxDrawerSetOpen(false);
      const first = range.querySelector('img');
      if (first) window.liteBox.click({ target: first });
    })();
  }

  // ==================== 清理失败引导（2026-10-13 用户裁定） ====================
  // 背景：explorer 等进程占着句柄的文件在内核层删不掉，旧文案「可关闭相关程序或
  // 重启后再试」在占用者就是 explorer 时无解（真机裁定原话：「真结束了资源管理器
  // 不就没了吗」）。两条出路都接现成原语：
  //   ① 重启资源管理器（contextmenu:restart-explorer，无损重启，桌面/任务栏几秒
  //      恢复）→ 自动对失败项重新执行（复用 clean() 的整条确认链）；
  //   ② 登记重启后删除（uninstall:pending-add → PendingFileRenameOperations，
  //      下次开机由系统删除；目录会被后端如实 skip，回执汇总展示）。

  // 收集待登记文件路径：**只认逐文件失败回执**（K12，2026-10-18）——
  //   · 常规清理项：回执 details 的 failedFiles（{path, reason}；后端只外发可延期的
  //     两档——被占用/权限不足，安全闸门拒绝的与已消失的不在其中）；
  //   · 文件清理项：回执明细里 status==='error' 且带 path 的行。
  // 拿不到逐文件明细的项（缺字段/旧回执）**不计入**：登记面不再拿条目目标路径或
  // 扫描清单全量顶替——那会把成功项也送去「重启后永久删」（K12 病灶本体）。
  function collectFailedPaths(items, details) {
    const byId = new Map();
    for (const d of details || []) {
      if (!d || !d.id) continue;
      if (!byId.has(d.id)) byId.set(d.id, []);
      byId.get(d.id).push(d);
    }
    const paths = [];
    for (const d of items) {
      for (const r of byId.get(d.id) || []) {
        if (Array.isArray(r.failedFiles)) {
          for (const f of r.failedFiles) if (f && f.path) paths.push(f.path);
        }
        // 文件清理项：error 行自带 path（fcDetails 映射保留，见 clean()）
        if (r.status === 'error' && r.path) paths.push(r.path);
      }
    }
    return [...new Set(paths)].filter(Boolean);
  }

  // K12：失败文件动辄上百，一次性全送会被后端整批拒「请分批登记」，故按后端单批上限切片顺序登记。
  // 上限不写在这里：真源在 Rust，读 tauri-api.js 的导出（F4a1-L09 撤掉了此处的本地字面量副本）。
  const PENDING_ADD_BATCH = window.ipcLimits.pendingAddMaxItems;

  function offerCleanupRetryPanel(items, execDetails) {
    if (!window.modal?.create) {
      // modal 缺席（理论不可达）：退回旧文案，至少不失声
      window.app?.toast('warning', `${items.length} 项未完全清理（部分文件可能被占用或需管理员权限，可重启后再试）`);
      return;
    }
    const listed = items.slice(0, 8);
    const overflow = items.length - listed.length;
    const rows = listed.map(d => {
      const sr = scanResults.get(d.id) || {};
      const label = sr.name || d.name || d.id;
      // R4（2026-10-15）：按因标注——权限不足与被占用分开（下一步动作不同）
      const note = (Number(d.residual) || 0) > 0 ? '部分残留（被占用）'
        : (Number(d.denied) || 0) > 0 ? '权限不足' : '清理失败';
      return `<div class="lock-app-row"><span class="lock-app-name" data-tip="${escapeHtml(sr.path || label)}">${escapeHtml(label)}</span><span class="lock-app-count">${note}</span></div>`;
    }).join('');
    const ctrl = window.modal.create({
      id: 'cleanupRetryModal-' + Date.now(),
      title: `${items.length} 项未完全清理`,
      bodyHtml: `
        <div class="confirm-message">以下项目未能完全删除（原因见各行标注；多为文件正被程序占用，部分是权限不足）。下面两个动作都不需要你手动结束任何程序：</div>
        <div class="lock-app-list">${rows}${overflow > 0 ? `<div class="lock-app-row"><span class="lock-app-name">…另有 ${overflow} 项</span></div>` : ''}</div>
        <div class="lock-critical-note">重启资源管理器是无损操作：桌面与任务栏会短暂消失后自动恢复，已打开的文件夹窗口会被关闭。</div>`,
      footerHtml: `
        <span class="model-picker-spacer"></span>
        <button class="btn btn-secondary" data-retry="pending" type="button">登记到重启后删除</button>
        <button class="btn btn-primary" data-retry="explorer" type="button">重启资源管理器并重试</button>`,
      onClose() { /* 面板可随时关，不做强制 */ }
    });
    const explorerBtn = ctrl.footer.querySelector('[data-retry="explorer"]');
    const pendingBtn = ctrl.footer.querySelector('[data-retry="pending"]');
    const failedIds = items.map(d => d.id);

    explorerBtn.addEventListener('click', async () => {
      const ok = await window.app?.confirmWarning(
        '重启资源管理器确认',
        '将结束并重新打开资源管理器（explorer.exe）：桌面与任务栏会短暂消失后自动恢复，已打开的文件夹窗口会被关闭。随后自动重试刚失败的清理项。',
        '重启并重试',
        '取消'
      );
      if (!ok) return;
      explorerBtn.disabled = true;
      explorerBtn.textContent = '正在重启...';
      try {
        await window.api.contextmenu.restartExplorer();
      } catch (e) {
        window.app?.toast('error', '重启资源管理器失败：' + ((e && e.message) || e));
        explorerBtn.disabled = false;
        explorerBtn.textContent = '重启资源管理器并重试';
        return;
      }
      // explorer 退出到重新拉起、句柄释放需要几秒；太早重试会再撞一次占用
      await new Promise(r => setTimeout(r, 3500));
      ctrl.close();
      selectedIds = new Set(failedIds.filter(id => scanResults.has(id)));
      updateUI();
      await clean();
    });

    pendingBtn.addEventListener('click', async () => {
      // K12：登记面只认逐文件失败回执（execDetails = 本次 clean() 的合并明细）
      const paths = collectFailedPaths(items, execDetails);
      if (!paths.length) {
        window.app?.toast('warning', '没有可登记的文件：本批没有逐文件失败明细（目录、已删除与受保护项不支持重启后删）');
        return;
      }
      // K12：PFRO 是**永久删**出口，登记前必须独立高危险确认（旧流程点了就登记，
      // 用户不知道是永久删）。文案三要素：重启后删除 / 不进回收站 / 重启前可撤回。
      const ok = await window.app?.confirmDanger(
        '登记重启后删除',
        `将把 ${paths.length} 个删除失败的文件登记为「下次重启时删除」。\n这是永久删除：不进回收站、无法还原；重启前可在本页「重启后删除」入口查看并撤回。`,
        '仍然登记',
        '取消',
        '删除动作由系统在重启的会话管理器阶段执行，Trim 不参与那一步；目录不支持该机制，登记时会被跳过。'
      );
      if (!ok) return;
      pendingBtn.disabled = true;
      pendingBtn.textContent = '正在登记...';
      // K12：按 PENDING_ADD_BATCH 切片顺序登记并聚合回执（单批超限会被后端整批拒）
      let added = 0;
      let skipped = 0;
      const failedRows = [];
      try {
        for (let i = 0; i < paths.length; i += PENDING_ADD_BATCH) {
          const resp = await window.api.uninstall.pendingAdd(paths.slice(i, i + PENDING_ADD_BATCH));
          if (!resp || !resp.success) throw new Error((resp && resp.message) || '登记失败');
          const data = resp.data || {};
          const rows = data.details || [];
          added += Number(data.added) || 0;
          skipped += rows.filter(r => r.status === 'skip').length;
          failedRows.push(...rows.filter(r => r.status === 'fail'));
        }
        window.app?.toast('success', `已登记 ${added} 个文件到重启后删除${skipped ? `；${skipped} 个跳过（目录/重复登记）` : ''}${failedRows.length ? `；${failedRows.length} 个登记失败` : ''}`);
        pendingBtn.textContent = added > 0 ? '已登记' : '无可登记项';
        pendingBtn.setAttribute('data-tip', '已登记的文件将在下次重启时由系统删除（重启前可撤回）');
        if (added === 0) pendingBtn.disabled = true;
        refreshPendingBadge();
      } catch (e) {
        window.app?.toast('error', '登记失败：' + ((e && e.message) || e));
        pendingBtn.disabled = false;
        pendingBtn.textContent = '登记到重启后删除';
      }
    });
  }

  // ==================== K13：重启后删除清单（主窗查看/撤回入口） ====================
  // 背景：登记项（PFRO + 待删台账）此前只在残留副窗可见可撤回——主窗清理域登记的
  // 条目在主窗没有任何入口（K13 缺口本体：看得见才算「可撤回」）。档位侧
  // uninstall:pending-list/revoke 已同 add 放到 PENDING_DELETE_WINDOWS（main+residue），
  // 这里补主窗侧的按钮 + 清单弹窗。
  const PENDING_STATUS_LABELS = {
    pending: '待重启删除',
    consumed: '已被重启消费',
    missing: '文件已不在'
  };

  /// 刷新「重启后删除」入口按钮：有待删条目才显示；台账损坏时置灰并明示（M-6 同口径）。
  function refreshPendingBadge() {
    const btn = document.getElementById('btnPendingList');
    if (!btn || !window.api?.uninstall?.pendingList) return;
    window.api.uninstall.pendingList().then(function (resp) {
      const data = (resp && resp.success && resp.data) || {};
      const entries = data.entries || [];
      const n = entries.filter(e => e.status === 'pending').length;
      const text = document.getElementById('btnPendingListText');
      if (data.degraded) {
        // 台账损坏 = 撤回凭据不可信：不隐藏按钮（用户该知道 PFRO 里可能还挂着），
        // 置灰 + data-tip 说明，与「真的没有待删项」区分开（残留副窗同口径）。
        btn.hidden = false;
        btn.disabled = true;
        if (text) text.textContent = '重启后删除（台账损坏）';
        btn.setAttribute('data-tip', '待删清单文件损坏，无法确认哪些条目仍挂起；PFRO 里的登记可能仍会在下次重启时执行。');
        return;
      }
      btn.disabled = false;
      btn.hidden = entries.length === 0;
      if (text) text.textContent = n > 0 ? `重启后删除（${n}）` : '重启后删除';
    }).catch(function () {
      // 读失败不显示入口：没有可确认的清单就不给「查看/撤回」的幻觉
      btn.hidden = true;
    });
  }

  /// 打开待删清单弹窗：三态分明（pending/consumed/missing）+ 撤回全部。
  async function openPendingListModal() {
    let resp;
    try {
      resp = await window.api.uninstall.pendingList();
    } catch (e) {
      window.app?.toast('error', '待删清单读取失败：' + ((e && e.message) || e));
      return;
    }
    const data = (resp && resp.success && resp.data) || {};
    if (data.degraded) {
      window.app?.toast('warning', '待删清单文件已损坏，无法确认哪些条目仍挂起；PFRO 里的登记可能仍会在下次重启时执行。');
      return;
    }
    const entries = data.entries || [];
    if (!entries.length) {
      window.app?.toast('info', '当前没有登记「重启后删除」的文件');
      refreshPendingBadge();
      return;
    }
    const rows = entries.map(e => {
      const label = PENDING_STATUS_LABELS[e.status] || e.status || '未知';
      const tip = e.target || '';
      return `<div class="lock-app-row"><span class="lock-app-name" data-tip="${escapeHtml(tip)}">${escapeHtml(tip)}</span><span class="lock-app-count">${escapeHtml(label)}</span></div>`;
    }).join('');
    const pendingN = entries.filter(e => e.status === 'pending').length;
    const ctrl = window.modal.create({
      id: 'pendingListModal-' + Date.now(),
      title: `重启后删除（${entries.length} 项登记）`,
      bodyHtml: `
        <div class="confirm-message">以下文件已登记为「下次重启时删除」。这是永久删除：不进回收站；<strong>重启前</strong>可撤回，撤回后文件保持原样。</div>
        <div class="lock-app-list">${rows}</div>`,
      footerHtml: `
        <span class="model-picker-spacer"></span>
        <button class="btn btn-secondary" data-role="close" type="button">关闭</button>
        <button class="btn btn-primary" data-role="revoke" type="button"${pendingN ? '' : ' disabled'}>撤回全部（${pendingN}）</button>`,
      onClose() { /* 面板可随时关，不做强制 */ }
    });
    ctrl.footer.querySelector('[data-role="close"]').addEventListener('click', () => ctrl.close());
    ctrl.footer.querySelector('[data-role="revoke"]').addEventListener('click', async () => {
      // P1-7（F4a1 同族）：旧写法只有 IPC 那一步在 try 里，**第一个 await（确认件）在外面** ——
      // `window.app` 在但 `confirmWarning` 缺失时 `window.app?.confirmWarning(...)` 是直接
      // 调用 undefined，抛 TypeError 变成 unhandled rejection；用户看到的是「点撤回没反应」，
      // 而这正是 AGENTS 例外 B「重启前可撤回」的唯一前端出口。整段收进一个 try 才有出口。
      try {
        // 撤回是**安全方向**（阻止删除、文件保留），走黄色确认即可；红色留给登记（永久删）。
        const ok = await window.app?.confirmWarning(
          '撤回重启后删除',
          `将把 ${pendingN} 个仍挂起的登记从系统中摘除：这些文件不会被删除，保持原样。已被重启消费或文件已不在的条目会一并从清单清除。`,
          '撤回全部',
          '取消',
          '撤回需要管理员权限（系统重启队列只允许管理员修改）；未提权时会失败且不动清单。'
        );
        if (!ok) return;
        const rr = await window.api.uninstall.pendingRevoke();
        if (!rr || !rr.success) throw new Error((rr && rr.message) || '撤回失败');
        window.app?.toast('success', `已撤回 ${(rr.data && rr.data.revoked) || 0} 项登记，相关文件不会被删除`);
        ctrl.close();
        refreshPendingBadge();
      } catch (e) {
        window.app?.toast('error', '撤回未完成：' + ((e && e.message) || e));
      }
    });
  }

  // ==================== P3 条目明细弹窗 ====================
  // 枚举单个条目将删除的具体文件清单（只读，最多展示 600 条），支持复制完整清单。
  // v3.2.0 弹窗统一批次：骨架改由 modal.js 工厂生成（Esc/遮罩/× 关闭统一）
  function closeItemDetail() {
    document.getElementById('itemDetailBackdrop')?.remove();
  }

  // ==================== C-4 备份还原（注册表 + 永久删文件批次） ====================

  function fmtBackupTime(ms) {
    if (!ms) return '—';
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  async function renderRegBackupList(ctrl) {
    const body = ctrl.body;
    let resp, respF, respU, respP;
    const failedSources = [];
    try {
      [resp, respF, respU, respP] = await Promise.all([
        window.api.cleanup.regBackupList(),
        window.api.cleanup.fileBackupList().catch(() => { failedSources.push('永久删文件备份'); return null; }),
        // D1（M5）：卸载域注册表备份此前只写不读，删错了没有任何还原入口
        window.api.uninstall.regBackupList().catch(() => { failedSources.push('卸载注册表备份'); return null; }),
        // HiBit §H1：卸载残留的自包含还原包（内容本体在 zip 里，能整批写回原位置）
        window.api.uninstall.batchList().catch(() => { failedSources.push('卸载还原包'); return null; })
      ]);
    } catch (e) {
      if (document.body.contains(body)) body.innerHTML = `<div class="empty-state"><p>备份列表读取失败: ${escapeHtml(e.message)}</p></div>`;
      return;
    }
    if (!document.body.contains(body)) return;
    const backups = (resp && resp.success && resp.data && resp.data.backups) || [];
    const manifests = (respF && respF.success && respF.data && respF.data.manifests) || [];
    const uninst = (respU && respU.success && respU.data && respU.data.backups) || [];
    const packData = (respP && respP.success && respP.data) || {};
    const packs = packData.packs || [];
    if (!backups.length && !manifests.length && !uninst.length && !packs.length) {
      // A1-L01：整段来源失败不能被渲染成「还没有备份」。
      body.innerHTML = failedSources.length
        ? `<div class="empty-state"><p>部分备份读取失败：${escapeHtml(failedSources.join('、'))}；其余来源也没有记录。</p></div>`
        : '<div class="empty-state"><p>还没有备份。清理含注册表项的条目会自动导出 .reg 备份；永久删除的文件会在 64MB/文件、256MB/批次上限内自动留副本。卸载残留可在清理前勾选「先备份内容再删」生成本机还原包。</p></div>';
      return;
    }
    // 「旧版」徽章：这份躺在升级前的老数据目录里（N1 跨根兜底才看得见）。
    // 不标来源的话用户会以为当前版本偷偷写了它，或以为它已经被清理掉了。
    const legacyBadge = (x) => (x && x.fromLegacy
      ? '<span class="badge off" data-tip="来自升级前的旧数据目录，仍可还原">旧版</span>' : '');
    const backupHead = (list, data, unit) => {
      const total = Number(data && data.totalCount) || list.length;
      const bytes = Number(data && data.totalBytes) || 0;
      const more = total > list.length ? `，显示最近 ${list.length} 份` : '';
      const size = bytes > 0 ? ` · 合计 ${formatSize(bytes)}` : '';
      return `${unit} · ${total} 份${more}${size}`;
    };
    const regSection = !backups.length ? '' :
      `<div class="finder-group-header"><span>${backupHead(backups, resp && resp.data, '注册表备份')}</span></div>
       <div class="detail-file-list">${backups.map((b, i) =>
        `<div class="detail-file-row"><span class="detail-file-path" data-tip="${escapeHtml(b.file)}">${fmtBackupTime(b.mtimeMs)} · ${escapeHtml(b.ruleId || '?')}${b.seq ? ` #${escapeHtml(b.seq)}` : ''} · ${formatSize(b.sizeBytes)} ${legacyBadge(b)}</span><button class="fileclean-preview-btn" data-reg-restore="${i}" type="button">还原</button></div>`
      ).join('')}</div>`;
    const fileSection = !manifests.length ? '' :
      `<div class="finder-group-header"><span>文件备份（永久删批次） · ${Number((respF && respF.data && respF.data.totalCount)) || manifests.length} 批${manifests.length < Number((respF && respF.data && respF.data.totalCount)) ? `，显示最近 ${manifests.length} 批` : ''}</span></div>
       <div class="detail-file-list">${manifests.map((m, i) =>
        `<div class="detail-file-row"><span class="detail-file-path" data-tip="${escapeHtml(m.file)}">${fmtBackupTime(m.mtimeMs)} · ${m.count} 个文件 · ${formatSize(m.totalSize)} ${legacyBadge(m)}</span><button class="fileclean-preview-btn" data-file-backup-view="${i}" type="button" data-tip="查看本批次条目并逐个还原">查看</button></div>`
      ).join('')}</div>`;
    // 卸载域备份：每行标出封条核对结果。seal 不是 ok 的行**不给还原按钮**——
    // 内容与封条不符的备份 import 回注册表，等于把可能被改写过的内容当可信还原
    const SEAL_TEXT = { ok: '封条相符', missing: '无封条（旧备份）', mismatch: '封条不符', corrupt: '封条损坏', unreadable: '备份不可读' };
    const uninstSection = !uninst.length ? '' :
      `<div class="finder-group-header"><span>${backupHead(uninst, respU && respU.data, '卸载残留注册表备份')}</span></div>
       <div class="detail-file-list">${uninst.map((b, i) => {
         const canRestore = b.seal === 'ok' || b.seal === 'missing';
         // 封条状态已经在行内文本里出现过，这里不重复它，只说明「为什么没有还原入口」
         const restoreBtn = canRestore
           ? `<button class="fileclean-preview-btn" data-uninst-restore="${i}" type="button">还原</button>`
           : `<span class="finder-name-text" style="opacity:.6" data-tip="封条核对未通过（${escapeHtml(b.seal)}），不提供还原入口">不可还原</span>`;
         return `<div class="detail-file-row"><span class="detail-file-path" data-tip="${escapeHtml(b.target || b.file)}">${fmtBackupTime(b.mtimeMs)} · ${escapeHtml(b.keyLeaf || b.file)} · ${formatSize(b.sizeBytes)} · ${escapeHtml(SEAL_TEXT[b.seal] || b.seal)} ${legacyBadge(b)}</span>${restoreBtn}</div>`;
       }).join('')}</div>`;
    // 还原包：zip 不在了就**不给还原按钮**（内容缺失时点下去只会逐条失败，不如这里说清）
    const packSection = !packs.length ? '' :
      `<div class="finder-group-header"><span>卸载还原包 · ${packs.length} 批（合计 ${formatSize(Number(packData.totalBytes) || 0)}）</span></div>
       <div class="detail-file-list">${packs.map((p, i) => {
         const canRestore = p.hasZip && !p.broken;
         const label = `${escapeHtml(p.id)} · ${p.files || 0} 个文件 · ${p.dirs || 0} 个目录 · ${formatSize(Number(p.bytes) || 0)}`;
         const btn = canRestore
           ? `<button class="fileclean-preview-btn" data-pack-restore="${i}" type="button">整批还原</button>`
           : `<span class="finder-name-text" style="opacity:.6" data-tip="${escapeHtml(p.broken || 'payload.zip 缺失')}">不可还原</span>`;
         return `<div class="detail-file-row"><span class="detail-file-path" data-tip="${escapeHtml(p.dir || '')}">${label}</span>${btn}</div>`;
       }).join('')}</div>`;
    body.innerHTML = regSection + uninstSection + packSection + fileSection;

    body.querySelectorAll('[data-pack-restore]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const p = packs[+btn.getAttribute('data-pack-restore')];
        if (!p) return;
        const ok = await window.app?.confirmDanger?.(
          '整批还原卸载内容',
          `将把还原包「${p.id}」里的 ${p.files || 0} 个文件与 ${p.dirs || 0} 个目录按原路径写回磁盘（合计 ${formatSize(Number(p.bytes) || 0)}）。`,
          '确认还原',
          '取消',
          '只写文件，不写注册表（注册表还原在上方「卸载残留注册表备份」那一栏）。目标已存在且内容与备份不同的项会被跳过而不覆盖；受保护路径一律拒绝。'
        );
        if (!ok) return;
        try {
          const r = await window.api.uninstall.batchRestore(p.id);
          if (r && r.success) {
            const d = r.data || {};
            const bad = (d.failed || []).length;
            window.app?.toast(bad ? 'warning' : 'success',
              bad ? `已还原 ${d.restored || 0} 项，${bad} 项未还原（详见提示）` : `已还原 ${d.restored || 0} 项`);
            if (bad) {
              window.app?.log?.('warn', `还原包 ${p.id} 未还原项：${(d.failed || []).slice(0, 3).map((f) => `${f.path}（${f.reason}）`).join('；')}`);
            }
          } else {
            window.app?.toast('error', (r && r.message) || '还原失败');
          }
        } catch (e) {
          window.app?.toast('error', '还原失败: ' + e.message);
        }
        renderRegBackupList(ctrl);
      });
    });

    body.querySelectorAll('[data-uninst-restore]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const b = uninst[+btn.getAttribute('data-uninst-restore')];
        if (!b) return;
        const ok = await window.app?.confirmDanger?.(
          '还原卸载残留的注册表备份',
          `将把备份「${b.keyLeaf || b.file}」（${fmtBackupTime(b.mtimeMs)}，目标 ${b.target || '未知'}）通过 reg import 合并回注册表。只加回备份时存在的键/值，不会删除之后产生的新数据。`,
          '确认还原',
          '取消',
          '还原会重新写入注册表内容。备份与封条同在本用户可写的目录里，封条只防半截写入与误改，不是防伪凭证；请确认这确实是要恢复的键。'
        );
        if (!ok) return;
        try {
          const r = await window.api.uninstall.regBackupRestore(b.file);
          if (r && r.success) {
            window.app?.toast('success', (r.data && r.data.message) || '备份已还原');
          } else {
            window.app?.toast('error', (r && r.message) || '还原失败');
          }
        } catch (e) {
          window.app?.toast('error', '还原失败: ' + e.message);
        }
      });
    });

    body.querySelectorAll('[data-reg-restore]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const b = backups[+btn.getAttribute('data-reg-restore')];
        if (!b) return;
        const ok = await window.app?.confirmDanger?.(
          '还原注册表备份',
          `将把备份「${b.ruleId || b.file}」（${fmtBackupTime(b.mtimeMs)}）通过 reg import 合并回系统注册表。只加回备份时存在的键/值，不会删除之后产生的新数据。`,
          '确认还原',
          '取消',
          '还原会重新写入注册表内容，请确认该备份对应你确实要恢复的清理操作。'
        );
        if (!ok) return;
        try {
          const r = await window.api.cleanup.regBackupRestore(b.file);
          if (r && r.success) {
            window.app?.toast('success', '注册表备份已还原');
          } else {
            window.app?.toast('error', (r && r.message) || '还原失败');
          }
        } catch (e) {
          window.app?.toast('error', '还原失败: ' + e.message);
        }
      });
    });

    // 文件批次：二级视图（点「查看」展开该批条目，逐条还原到原路径）
    body.querySelectorAll('[data-file-backup-view]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const m = manifests[+btn.getAttribute('data-file-backup-view')];
        if (!m) return;
        try {
          // 明细直接读 manifest 不可行（渲染层无文件读取面），逐批列出由后端扩展——
          // 这里用最简实现：还原动作按「整批还原」逐条调 restore(index)，后端逐条判
          // 存在性跳过已存在的目标。先给用户确认，再顺序还原。
          const ok = await window.app?.confirmDanger?.(
            '还原文件备份',
            `将把「${fmtBackupTime(m.mtimeMs)}」批次的 ${m.count} 个文件逐个拷回原路径。目标位置已存在的文件会自动跳过，不会覆盖。`,
            '开始还原',
            '取消',
            '还原只加回文件，不删除任何现有数据。'
          );
          if (!ok) return;
          let restored = 0;
          let skipped = 0;
          for (let i = 0; i < m.count; i++) {
            const r = await window.api.cleanup.fileBackupRestore(m.file, i);
            if (r && r.success && r.data && r.data.restored) restored++;
            else skipped++;
          }
          window.app?.toast(restored ? 'success' : 'info', `还原完成：恢复 ${restored} 个文件，跳过 ${skipped} 个`);
        } catch (e) {
          window.app?.toast('error', '还原失败: ' + (e.message || e));
        }
      });
    });
  }

  // U1-d（2026-10-01）：备份还原从磁盘清理工具栏的二级按钮提到一级页面。
  // 原来藏在清理页最右侧，等于把「还原」这条退路摆在用户最不容易看见的位置；
  // 渲染逻辑（renderRegBackupList）只依赖 ctrl.body，所以搬页面不用改它。
  function renderBackupsPage() {
    const body = document.getElementById('backupsPageBody');
    if (!body) return;
    body.innerHTML = '<div class="empty-state"><p>正在读取备份列表…</p></div>';
    renderRegBackupList({ body });
  }

  // G-4 修订（2026-10-07）：回收站行「明细」= 打开系统回收站（条目清单由系统窗口承载）
  async function openSystemRecycleBin() {
    if (!window.api?.cleanup?.openRecycleBin) return;
    try {
      const resp = await window.api.cleanup.openRecycleBin();
      if (resp && resp.success === false) {
        window.app?.toast('error', resp.message || '打开系统回收站失败');
      }
    } catch (err) {
      window.app?.toast('error', '打开系统回收站失败: ' + (err.message || err));
    }
  }

  function openItemDetail(id) {
    const result = scanResults.get(id);
    const item = getItemById(id);
    closeItemDetail();
    const ctrl = window.modal.create({
      id: 'itemDetailBackdrop',
      title: `${(item && item.name) || id} · 文件明细`,
      bodyHtml: '<div class="empty-state"><p>正在枚举文件清单…</p></div>',
      footerClass: 'pw-footer',
      footerHtml: `
          <span class="pw-last-scan" data-role="meta"></span>
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary" data-role="copyBtn" type="button">复制完整清单</button>
          <button class="btn btn-primary" data-role="doneBtn" type="button">关闭</button>`
    });
    const backdrop = ctrl.backdrop;
    const body = ctrl.body;
    ctrl.footer.querySelector('[data-role="doneBtn"]').addEventListener('click', closeItemDetail);

    (async () => {
      try {
        const resp = await window.api.cleanup.itemDetail(id, (result && result.path) || '');
        if (!document.body.contains(body)) return;
        if (!resp || !resp.success) {
          body.innerHTML = `<div class="empty-state"><p>${escapeHtml((resp && resp.message) || '明细枚举失败')}</p></div>`;
          return;
        }
        const { kind, total, truncated, files } = resp.data;
        const meta = ctrl.footer.querySelector('[data-role="meta"]');
        if (kind === 'reg') {
          body.innerHTML = `<div class="empty-state"><p>注册表条目（共 ${total} 项键/值），不产生文件清单。</p></div>`;
        } else if (kind === 'dism') {
          body.innerHTML = `<div class="empty-state"><p>DISM 组件清理为系统级操作，不产生文件清单。</p></div>`;
        } else if (!files.length) {
          body.innerHTML = `<div class="empty-state"><p>未枚举到文件（目录为空或已被清理）。</p></div>`;
        } else {
          body.innerHTML = `<div class="detail-file-list">${files.map(f =>
            `<div class="detail-file-row"><span class="detail-file-path" data-tip="${escapeHtml(f.path)}">${escapeHtml(xtable.middleEllipsis(f.path, 96))}</span><span class="detail-file-size">${formatSize(f.size)}</span></div>`
          ).join('')}</div>`;
        }
        if (meta) meta.textContent = `共 ${total} 个文件${truncated ? '（仅展示前 600 条）' : ''}`;
        ctrl.footer.querySelector('[data-role="copyBtn"]').addEventListener('click', async () => {
          if (!files.length) return;
          try {
            await navigator.clipboard.writeText(files.map(f => f.path).join('\r\n'));
            window.app?.toast('success', `已复制 ${files.length} 条文件路径`);
          } catch (e) {
            window.app?.toast('error', '复制失败: ' + e.message);
          }
        });
      } catch (e) {
        if (document.body.contains(body)) body.innerHTML = `<div class="empty-state"><p>明细枚举失败: ${escapeHtml(e.message)}</p></div>`;
      }
    })();
  }

  // 导出「本次将清理」的 Markdown 计划清单（2026-10-06 任务四）：扫描勾选后、执行前
  // 一键另存（Rust 侧走保存对话框，口径同日志导出）。只读扫描结果与勾选状态，不触删除链。
  function init() {
    // F4a1-M03：灯箱的点击监听在 litebox.js 装载那一刻就挂在 document 上，原先只有第一次
    // 点「预览」才收窄到 #liteboxRange。窗口期内（已进清理页、尚未预览）主窗任何 <img>
    // 点击都会被劫持成全屏黑底灯箱（卸载列表图标、壁纸缩略图都算），还和该行自己的
    // click 处理叠加。收窄动作提到装载即做，之后每次 openPreview 仍会确认容器在不在。
    ensureLiteboxRange();
    renderCategoryList();
    updateUI();

    document.getElementById('btnScan')?.addEventListener('click', scan);
    document.getElementById('btnClean')?.addEventListener('click', clean);
    document.getElementById('btnSelectAll')?.addEventListener('click', toggleSelectAll);
    // K13：重启后删除清单入口（有待删条目才显示；登记/撤回后刷新）
    document.getElementById('btnPendingList')?.addEventListener('click', openPendingListModal);
    refreshPendingBadge();
    document.getElementById('btnRefreshBackups')?.addEventListener('click', renderBackupsPage);
    // C1-1 占用查询：查询 / 回车提交 / 结束进程（结束为不可逆操作，内部走 confirmDanger）
    document.getElementById('lockQueryBtn')?.addEventListener('click', () => runLockQuery());
    document.getElementById('lockQueryPath')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); runLockQuery(); }
    });
    document.getElementById('lockKillBtn')?.addEventListener('click', () => killLockedFromQuery());

    // P1-12：订阅扫描逐项进度（一次性；ipcRenderer.on 会累积，不能放进 scan）
    if (window.api?.cleanup?.onScanProgress) {
      window.api.cleanup.onScanProgress(onScanProgress);
    }
    // 2026-10-12：订阅执行逐项进度（清理大目录耗时长时进度条不再假走 90% 后冻结）
    if (window.api?.cleanup?.onExecuteProgress) {
      window.api.cleanup.onExecuteProgress(function (payload) {
        if (execProgressSink) execProgressSink(payload);
      });
    }

    // P1-9：Electron 运行时从 cleanup-rules.json（唯一数据源）加载分类，
    // 成功后覆盖 FALLBACK 并重算 ALL_IDS、重渲染。浏览器预览模式跳过。
    loadRulesFromMain();

    initAgePolicy();
  }

  // ==================== G-2 全局年龄门槛（设置页控件） ====================
  // 只收紧不放宽：后端把规则阈值与全局阈值取更严格的那个（max），且只作用于
  // 已声明时间门槛的规则。**真源是 Rust 侧策略文件**（数据目录里的
  // cleanup-min-age-days.txt）—— 这里不落 localStorage，避免出现第二真源；
  // 读不到就保持「关闭」的展示，提交结果一律以后端回执为准。
  const AGE_POLICY_TIERS = [0, 14, 30]; // 与后端 cleanup/set-age-policy 的档位闸一致
  function renderAgePolicyHint(days) {
    const hint = document.getElementById('cleanupAgeHint');
    if (!hint) return;
    hint.textContent = days > 0
      ? `已启用 ${days} 天：规则自身门槛更严格时按规则执行；本项只会让门槛更严，不会放宽。`
      : '已关闭：完全按每条规则自身的门槛执行（与升级前一致）。';
  }
  function initAgePolicy() {
    const sel = document.getElementById('cleanupAgePolicy');
    if (!sel || !window.api?.cleanup?.agePolicy) return;
    window.api.cleanup.agePolicy().then(function (resp) {
      const days = resp && resp.success && resp.data ? Number(resp.data.days) || 0 : 0;
      if (AGE_POLICY_TIERS.includes(days)) sel.value = String(days);
      renderAgePolicyHint(days);
    }).catch(function () {
      // 读失败不冒充「已关闭」：把不确定性说出来，用户仍可重新选择
      const hint = document.getElementById('cleanupAgeHint');
      if (hint) hint.textContent = '当前设置读取失败，可重新选择一次以写入。';
    });
    sel.addEventListener('change', function () {
      const days = Number(sel.value);
      if (!AGE_POLICY_TIERS.includes(days)) return; // DOM 被改也不提交非法档
      window.api.cleanup.setAgePolicy(days).then(function (resp) {
        if (resp && resp.success) {
          renderAgePolicyHint(days);
          window.app?.toast?.('success', days > 0 ? `清理年龄门槛已设为 ${days} 天` : '清理年龄门槛已关闭');
        } else {
          // 失败要把选择器拨回旧值，否则界面显示的和实际生效的不一致
          window.api.cleanup.agePolicy().then(function (r2) {
            const cur = r2 && r2.success && r2.data ? Number(r2.data.days) || 0 : 0;
            if (AGE_POLICY_TIERS.includes(cur)) sel.value = String(cur);
            renderAgePolicyHint(cur);
          }).catch(function () {});
          window.app?.toast?.('error', (resp && resp.message) || '年龄门槛写入失败');
        }
      }).catch(function (e) {
        window.app?.toast?.('error', '年龄门槛写入失败：' + ((e && e.message) || e));
      });
    });
  }

  // C2（2026-09-14 重复点审查）：HDD 上隐藏 Prefetch 清理项 ——
  // HDD 依赖预读与 Prefetch 缓存，清掉反而拖慢；SSD 上保留（清掉无损失）。
  // 探测失败或介质未知 → 不隐藏任何条目。
  function filterRulesByDiskType(groups, dt) {
    if (!dt || !dt.known || dt.isSsd) return groups;
    const drop = new Set(['prefetchFiles']);
    return groups.map(g => {
      const out = Object.assign({}, g);
      if (Array.isArray(g.items)) out.items = g.items.filter(it => !drop.has(it.id));
      if (Array.isArray(g.subGroups)) {
        out.subGroups = g.subGroups.map(sg => Object.assign({}, sg, {
          items: Array.isArray(sg.items) ? sg.items.filter(it => !drop.has(it.id)) : sg.items
        }));
      }
      return out;
    });
  }

  async function loadRulesFromMain() {
    if (!window.api?.cleanup?.rules) return; // 预览模式或旧 preload：沿用 FALLBACK
    try {
      // 磁盘介质探测与规则拉取并行；探测失败不阻塞规则加载
      const pDisk = window.api.system?.diskType
        ? window.api.system.diskType().then(r => (r && r.success ? r.data : null)).catch(() => null)
        : Promise.resolve(null);
      const [dt, resp] = await Promise.all([pDisk, window.api.cleanup.rules()]);
      if (resp && resp.success && resp.data && Array.isArray(resp.data.groups)) {
        const groups = filterRulesByDiskType(resp.data.groups, dt);
        CATEGORIES = buildCategoriesFromRules(Object.assign({}, resp.data, { groups }));
        rebuildItemIndex(); // CATEGORIES 换血 ⇒ id 索引必须同步重建（性能 v3 ③ 的另一处赋值点）
        ALL_IDS = getAllIds();
        renderCategoryList();
        updateUI();
      }
    } catch (e) {
      // 加载失败静默回退到 FALLBACK，不影响功能
    }
  }

  window.cleanup = {
    init,
    scan,
    clean,
    formatSize,
    MOCK_SIZES,
    // U1-d：一级「备份还原」页的进页钩子（app.js switchPage 调）
    onBackupsEnter: renderBackupsPage,
    // 执行中标记：当前**无消费方**（现算 src/scripts 只有本文件自己读 isCleaning）。
    // 保留导出是给「优雅关闭前判断清理是否在跑」留的位置（执行中最长可到 10 分钟），
    // 但那条判断并没有被 app.js 接上——旧注释把它写成已有能力，等于给下一个读者假依据。
    isCleaning: () => isCleaning
  };
})();
