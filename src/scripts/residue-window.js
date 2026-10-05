// residue-window.js - 「应用卸载残留扫描」副窗口（v0.7.0 起是残留链的唯一界面）。
//
// 用户拍板（2026-10-05）：主窗那段内联面板整块搬进来，卸载成功后弹的也是这一扇。
// 于是本页同时承载两条来路完全不同的链，**刻意不合并成一张表**：
//   ① 三链候选（规则库 / 失效登记 / 卸载遗留）—— v0.7.0 起可勾选、可删，走
//      `uninstall:residue-execute`，后端按本窗 label 分槽的执行快照是唯一闸门；
//   ② 七个深扫器报告（服务/驱动/fltmc/IFEO/厂商键/能力授权/游戏库）—— 只读，
//      后端同轮保证不写执行快照（`residue_deep.rs` 的常驻断言守着），
//      所以这一区**没有勾选框**，前文把 defaultChecked 当断言用的写法继续保留。
// 「有保护的不允许删除，没有保护的自行确认是否删除」= ②里的 protected 区只出说明、
// ①里的 deleteCapable===false 行永远画不出勾选框。
//
// 注意：独立窗口未加载 app.js —— toast 走 scripts/sub-toast.js（window.app 在本窗不存在），
// 高危确认走 scripts/modal.js 的 window.modal.confirm（app.js 的 confirmDanger 在本窗没有）。
// **确认件缺席即拒绝执行**：modal.js 没加载成功时宁可报"无法确认"，也不许跳过确认直接删。
(function () {
  'use strict';

  function el(id) { return document.getElementById(id); }
  function esc(s) { return window.ds.esc(String(s == null ? '' : s)); }
  function toast(type, message) { window.subToast?.hintLine('rsGlobalHint', type, message); }

  // 与主窗同一个键：同一 origin 的 localStorage 是共享的，偏好不该有两份真源
  const BACKUP_PREF_KEY = 'trim.residue.backupPack';
  function readBackupPref() { try { return localStorage.getItem(BACKUP_PREF_KEY) === '1'; } catch (e) { return false; } }
  function writeBackupPref(on) { try { localStorage.setItem(BACKUP_PREF_KEY, on ? '1' : '0'); } catch (e) { /* 写不进去就用当前值，不拦删除 */ } }

  const CONF_LABEL = { high: '高置信', medium: '中置信', low: '低置信（建议人工核对）' };
  const KIND_LABEL = { reg_key: '注册表项', reg_value: '注册表值', folder: '目录', file: '文件', shortcut: '快捷方式' };
  const DEAD_CLASS_TITLE = {
    uninstall: '失效卸载项',
    appPaths: '失效 App Paths',
  };

  // appId 从哪来：主窗卸载成功后经 URL query 带进来（后端开窗前先过取值闸）；
  // 副窗已开着时同一份值走 `residue:target` 事件。两处拿到的都还要再过一次
  // 执行侧的 `app_id 格式错误` 闸 —— 这里的前置判断只为少发一次无谓请求，不当安全边界用。
  const state = {
    appId: '',
    rows: [],            // 三链候选（扁平数组，勾选按全局下标寻址）
    deepRows: [],        // 深扫区**可删**的那一撮（deleteCapable=true，后端类白名单决定）
    scanGroups: [],
    report: null,        // 深扫报告
    filter: '',
    pendingFailed: [],
    running: false,
    scanning: false,
    protOpen: undefined,  // 已保护项手风琴：undefined=默认折叠；true=手动展开过（搜索清空也不收回）
  };

  function targetFromSearch() {
    try {
      return new URLSearchParams(location.search).get('app') || '';
    } catch (e) { return ''; }
  }

  function passes(item) {
    const q = state.filter.trim().toLowerCase();
    if (!q) return true;
    const d = item.details || {};
    const hay = [item.target, item.class, item.reason, item.kind, d.serviceName, d.image, d.installDir, d.ownerName]
      .filter(function (v) { return typeof v === 'string' && v; })
      .join('\n')
      .toLowerCase();
    return hay.indexOf(q) >= 0;
  }

  // ==================== ① 三链候选 ====================

  async function scanChains() {
    const box = el('rsChainBody');
    state.scanning = true;
    box.innerHTML = '<div class="finder-empty">正在扫描三类残留…</div>';
    const app = state.appId;
    const fail = (e) => ({ success: false, message: String((e && e.message) || e) });
    const [rApp, rDead, rOrphan] = await Promise.all([
      app ? window.api.uninstall.residueScan(app).catch(fail) : Promise.resolve(null),
      window.api.uninstall.deadScan().catch(fail),
      window.api.uninstall.orphanScan().catch(fail),
    ]);
    const groups = [];
    if (!app) {
      groups.push({ title: '程序残留', rows: [], hint: '未选中程序。从卸载页某一行的「查残留」进来，就会带上它的规则库残留。' });
    } else if (rApp && rApp.success) {
      const name = (rApp.data && rApp.data.appName) || '';
      groups.push({ title: `程序残留 · ${name}`, rows: (rApp.data && rApp.data.findings) || [] });
    } else {
      groups.push({ title: '程序残留', rows: [], hint: ((rApp && rApp.message) || '本组扫描失败') });
    }
    if (rDead && rDead.success) {
      groups.push({ title: '失效残留 · 全机', rows: (rDead.data && rDead.data.findings) || [], byClass: true });
    } else {
      groups.push({ title: '失效残留 · 全机', rows: [], hint: ((rDead && rDead.message) || '本组扫描失败') });
    }
    if (rOrphan && rOrphan.success) {
      groups.push({ title: '卸载遗留', rows: (rOrphan.data && rOrphan.data.findings) || [] });
    } else {
      // 这一组拒绝扫描是**正确行为**（档案为空时拿空集会被读成"这台机器没有遗留"）
      groups.push({ title: '卸载遗留', rows: [], hint: ((rOrphan && rOrphan.message) || '本组未执行') });
    }
    state.scanGroups = groups;
    state.rows = groups.reduce(function (acc, g) { return acc.concat(g.rows); }, []);
    // 勾选初值在渲染前定好：只展示不给删的行永远不该被勾上
    // 勾选初值在渲染前定好：只展示不给删的行永远不该被勾上。
    // 2026-10-06 用户裁定：进残留列表后可直接执行删除 ⇒ 后端判可删的候选一律默认勾上
    // （原口径「除规则库高置信项外不自动勾选」废止）；删除仍走逐批确认，保护项不给勾。
    state.rows.forEach(function (f) { f._checked = f.deleteCapable !== false; });
    renderChains();
    updateActionButtons();
    state.scanning = false;
    const n = state.rows.length;
    const notes = (rDead && rDead.success && rDead.data.notes && rDead.data.notes.length) ? rDead.data.notes[0] : '';
    toast(n ? 'info' : 'success', n ? `三链候选共 ${n} 项，可删项已默认勾选，确认后即可执行删除` : (notes || '三类扫描都没有发现残留'));
  }

  function chainTableHtml(title, rows) {
    let h = '<div class="finder-group-header" style="margin-top:8px;font-size:12px;opacity:.8"><span>' + esc(title) + ' · ' + rows.length + ' 项</span></div>';
    h += '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>目标</th><th style="width:110px">置信度</th><th style="width:96px">详情</th></tr></thead><tbody>';
    for (const f of rows) {
      const i = state.rows.indexOf(f);
      const cell = f.deleteCapable === false
        ? '<span class="finder-name-text" style="opacity:.5" data-tip="本链只登记、不删除">—</span>'
        : '<span class="checkbox' + (f._checked ? ' checked' : '') + '" data-rcheck="' + i + '" tabindex="0" role="checkbox" aria-checked="' + (f._checked ? 'true' : 'false') + '"></span>';
      const ignoreBtn = f.origin === 'orphan'
        ? '<button class="btn btn-secondary rs-mini-btn" data-orphan-ignore="' + i + '" data-tip="此后不再按这条卸载记录提示遗留数据（只影响应用数据遗留这一组，不动残留规则库）">不再提示该程序</button>'
        : '';
      h += '<tr class="' + (f._checked ? 'finder-row-selected' : '') + '">'
        + '<td>' + cell + '</td>'
        + '<td><div class="finder-cell"><span class="finder-path-text">' + esc(f.target) + '</span></div>'
        + '<div class="xtable-cell-muted">' + esc(f.reason || '') + '</div>' + ignoreBtn + '</td>'
        + '<td class="finder-col-size"><span class="finder-name-text" style="opacity:.75">' + esc(CONF_LABEL[f.confidence] || f.confidence || '—') + '</span></td>'
        // 行上只留一行结论，"在哪 / 能不能删 / 为什么"三点全在详情里（用户 2026-10-05：信息过于冗余）
        + '<td class="finder-col-size"><button class="btn btn-secondary rs-mini-btn" data-detail="c:' + i + '" data-tip="查看落点、可否删除与判定依据">点击查看</button></td>'
        + '</tr>';
    }
    return h + '</tbody></table>';
  }

  function chainGroupHtml(g) {
    let h = '<div class="finder-group-header" style="margin-top:14px"><span>' + esc(g.title) + ' · ' + g.rows.length + ' 项</span></div>';
    const shown = g.rows.filter(passes);
    if (!g.rows.length) return h + '<div class="finder-empty">' + esc(g.hint || '本组没有候选。') + '</div>';
    if (!shown.length) return h + '<div class="finder-empty">' + esc('本组有 ' + g.rows.length + ' 项，但没有匹配当前搜索的。') + '</div>';
    if (g.byClass) {
      for (const cls of ['uninstall', 'appPaths']) {
        const rows = shown.filter(function (f) { return f.deadClass === cls; });
        if (rows.length) h += chainTableHtml(DEAD_CLASS_TITLE[cls] || cls, rows);
      }
      return h;
    }
    const regs = shown.filter(function (f) { return f.kind === 'reg_key' || f.kind === 'reg_value'; });
    const files = shown.filter(function (f) { return f.kind !== 'reg_key' && f.kind !== 'reg_value'; });
    if (regs.length) h += chainTableHtml('注册表', regs);
    if (files.length) h += chainTableHtml('文件与目录', files);
    return h;
  }

  function renderChains() {
    const box = el('rsChainBody');
    if (!state.scanGroups.length) {
      box.innerHTML = '<div class="finder-empty">还没扫。点上方「重新扫描」跑三条链。</div>';
      return;
    }
    if (!state.rows.length && !state.scanGroups.some(function (g) { return g.rows.length; })) {
      box.innerHTML = '<div class="finder-empty">三条链都没有发现残留。</div>' + state.scanGroups.map(chainGroupHtml).join('');
      return;
    }
    box.innerHTML = state.scanGroups.map(chainGroupHtml).join('');
  }

  // ==================== ② 七个深扫器（只读） ====================

  async function scanDeep() {
    const box = el('rsDeepBody');
    el('rsDeepSummary').textContent = '正在扫描…';
    box.innerHTML = '<div class="finder-empty"><p>正在读取服务表、驱动目录与注册表残留…</p></div>';
    try {
      const res = await window.api.uninstall.residueDeepScan();
      if (!res || res.success !== true) throw new Error((res && res.message) || '扫描命令返回失败');
      state.report = res.data && res.data.report ? res.data.report : null;
      if (!state.report) throw new Error('回执里没有报告数据');
      renderDeep();
      toast('info', '深扫完成');
    } catch (e) {
      box.innerHTML = '<div class="finder-empty">深扫失败：' + esc(e && e.message ? e.message : e) + '</div>';
      toast('error', '深扫失败：' + (e && e.message ? e.message : e));
    }
  }

  function deepTableHtml(title, items, groupKind) {
    const head = '<div class="finder-group-header" style="margin-top:14px"><span>' + esc(title) + ' · ' + items.length + ' 项</span></div>';
    if (!items.length) return head + '<div class="finder-empty">' + esc('本组没有候选。') + '</div>';
    const rows = items.map(function (it, idx) {
      // 只读区的断言仍在：后端不该给「默认勾选」的候选（危险能力默认关，§9.2）
      const drift = it.defaultChecked === true ? ' <span class="badge badge-warn">形态漂移：本阶段不该有默认勾选项</span>' : '';
      const gi = state.groupsIndex.get(title) || [];
      gi.push({ item: it, kind: groupKind, idx: idx });
      state.groupsIndex.set(title, gi);
      // 可删与否**只信后端的 deleteCapable**（它由快照集合反推，§5.16）；
      // protected 区整块传 groupKind='protected'，永远画不出勾选框
      const can = groupKind !== 'protected' && it.deleteCapable === true;
      let cell;
      if (groupKind === 'protected') {
        cell = '<span class="finder-name-text" style="opacity:.5" data-tip="受保护：不允许删除，只说明为什么">保护</span>';
      } else if (can) {
        // 勾选态记在**报告项本身**（不是副本）：搜索框每敲一次都会重渲染这一区，
        // 记在副本上等于「一改搜索就悄悄取消勾选」
        // 2026-10-06 用户裁定：可删候选默认勾上（删除仍走确认，保护项画不出勾选框）
        if (typeof it._checked !== 'boolean') it._checked = true;
        const di = state.deepRows.push(it) - 1;
        it._deepIdx = di;
        cell = '<span class="checkbox' + (it._checked ? ' checked' : '') + '" data-dcheck="' + di
          + '" tabindex="0" role="checkbox" aria-checked="' + (it._checked ? 'true' : 'false') + '"></span>';
      } else {
        cell = '<span class="finder-name-text" style="opacity:.5" data-tip="这一类不进执行快照：删除判据还没评审过，或删了也不解决问题">—</span>';
      }
      return '<tr>'
        + '<td style="width:34px">' + cell + '</td>'
        + '<td><div class="xtable-cell-path">' + esc(it.target) + '</div>'
        + '<div class="xtable-cell-muted">' + esc(it.reason || '') + drift + '</div></td>'
        + '<td style="width:96px"><button class="btn btn-secondary rs-mini-btn" data-detail="d:' + esc(title) + ':' + idx + '" data-tip="查看落点、可否删除与判定依据">点击查看</button></td>'
        + '</tr>';
    }).join('');
    return head + '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>目标</th><th style="width:96px">详情</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  function summaryHtml(r) {
    const s = r.scanned || {};
    const total = (r.groups || []).reduce(function (n, g) { return n + (g.count || 0); }, 0);
    const platform = r.platforms || {};
    const parts = [
      '候选合计 ' + total + ' 项',
      '已保护 ' + (r.protectedCount || 0) + ' 项',
      '服务 ' + (s.services || 0),
      '驱动文件 ' + (s.driverFiles || 0),
      '挂载滤镜 ' + (s.mountedFilters || 0),
      'IFEO ' + (s.ifeoKeys || 0),
      '厂商产品键 ' + (s.vendorProductKeys || 0),
      '平台记录 ' + (s.platformRecords || 0)
    ];
    let html = '<div class="xtable-cell-text">' + parts.map(esc).join(' · ') + '</div>';
    if (platform.unreadable && platform.unreadable.length) {
      html += '<div class="xtable-cell-hint">平台清单未读全：' + esc(platform.unreadable.join('、'))
        + ' —— 这些平台的「游戏已卸载」判定本轮不成立，反作弊候选已按证据不足降级为不报。</div>';
    }
    const notes = Array.isArray(r.notes) ? r.notes : [];
    if (notes.length) {
      html += '<div class="xtable-cell-desc">' + notes.map(function (n) { return '· ' + esc(n); }).join('<br>') + '</div>';
    }
    return html;
  }

  function renderDeep() {
    state.groupsIndex = new Map();
    state.deepRows = [];
    const body = el('rsDeepBody');
    const r = state.report;
    if (!r) { body.innerHTML = '<div class="finder-empty">尚无深扫结果。</div>'; return; }
    if (r.fatal) {
      el('rsDeepSummary').textContent = '深扫失败';
      body.innerHTML = '<div class="finder-empty">' + esc(r.fatal) + '</div>';
      return;
    }
    el('rsDeepSummary').innerHTML = summaryHtml(r);
    const groups = (r.groups || []).map(function (g) {
      return deepTableHtml(g.title, (g.items || []).filter(passes), 'group');
    }).join('');
    const protectedItems = (r.protected || []).filter(passes);
    // 「有保护的不允许删除」就在这一栏：只给说明，不给勾选、不给按钮。
    // §2.6b：默认折叠成手风琴（行数可达数百，常驻展开会把可执行区挤出视野）；
    // 搜索命中时自动展开（否则「搜到了却看不见」），手动展开过则搜索清空也不收回。
    const protHtml = protectedItems.length ? protectedAccordionHtml(protectedItems) : '';
    body.innerHTML = groups + protHtml;
  }

  /// 已保护项手风琴（§2.6b）：复用 finder 空文件/空目录页的 .empty-pane 件（main.css 现成样式，
  /// 零新增 token）。表格本体仍由 deepTableHtml 产出（title 参与详情寻址，必须与普通组一致），
  /// 这里只剥掉普通组头、换上手风琴头；折叠态由「手动开合 + 搜索命中」两个信号共同决定。
  function protectedAccordionHtml(items) {
    const inner = deepTableHtml('已保护项', items, 'protected');
    const table = inner.slice(inner.indexOf('<table'));
    const open = state.protOpen === true || !!(state.filter.trim());
    return '<section class="empty-pane' + (open ? '' : ' collapsed') + '" data-rs-acc>'
      + '<button class="empty-pane-head" type="button" aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<span class="empty-pane-chevron">▾</span>'
      + '<span class="empty-pane-title">已保护项</span>'
      + '<span class="empty-pane-count">' + items.length + ' 项</span>'
      + '</button>'
      + '<div class="empty-pane-body">' + table + '</div>'
      + '</section>';
  }

  // ==================== 详情（点击查看） ====================

  function contribRows(item) {
    const list = Array.isArray(item.contribs) ? item.contribs : [];
    if (!list.length) return '<div class="xtable-cell-muted">后端没有给出贡献项。</div>';
    return list.map(function (c) {
      return '<div class="rs-contrib"><span class="rs-contrib-code">' + esc(c.code || '') + '</span><span>' + esc(c.text || '') + '</span></div>';
    }).join('');
  }

  function detailRows(d) {
    const LABELS = {
      serviceName: '服务名', imagePath: 'ImagePath', landing: '落点', landingExists: '落点存在',
      start: '启动类型', type: '服务类型', state: '当前状态', rawState: '状态原值',
      signer: '签名主体', antiCheat: '反作弊标记', inLibraryGame: '在库游戏', image: '镜像名',
      depends: '依赖', filterName: '滤镜名', altitude: '加载高度', class: '类别',
      ownerName: '来源程序', ownerId: '来源卸载键', valueNames: '键内值名', subkeyCount: '子键数',
      debugger: 'Debugger', installDir: '安装目录', publisher: '发行商', kind: '形状',
      note: '备注', platform: '平台', unreadable: '平台清单未读全', target: '目标'
    };
    const keys = Object.keys(d || {});
    if (!keys.length) return '<div class="xtable-cell-muted">这条没有附加明细。</div>';
    return '<table class="finder-table"><tbody>' + keys.map(function (k) {
      const v = d[k];
      const shown = Array.isArray(v) ? v.join('、') : (typeof v === 'boolean' ? (v ? '是' : '否') : String(v));
      return '<tr><td style="width:150px"><span class="finder-name-text" style="opacity:.7">' + esc(LABELS[k] || k) + '</span></td><td><span class="finder-path-text">' + esc(shown) + '</span></td></tr>';
    }).join('') + '</tbody></table>';
  }

  // 可否删：三链看 deleteCapable；深扫区只看后端回带的 deleteCapable ——
  // 那个标记由快照集合反推（residue_deep.rs），前端不再自己判一遍类白名单（§5.16）。
  // 这里只负责把「为什么不给删」说清楚，判据不在这一层。
  function deletableText(item, from) {
    if (from === 'deep') {
      if (item.deleteCapable === true) {
        if (item.kind === 'reg_key') {
          // 服务键的还原语义必须说全：.reg 还原是「把键加回来」，不恢复删除那一刻的
          // 运行态（服务不会自动重新起来），且 SCM 读到新键可能要重启。§9.3：不写「一键还原」
          return '可以删除：八道判据此刻全部现读通过（落点已失踪、不在系统目录、非内核驱动、'
            + '非 boot/system 启动、无依赖声明、不在反作弊名单）。删除前会先整键导出 .reg 备份；'
            + '还原是把键加回去，不恢复运行状态，可能需重启才生效。已提权才允许执行。';
        }
        return '可以删除：移入回收站（可还原），不进永久删兜底。勾上之后仍要逐项确认。';
      }
      const WHY = {
        orphan_sys_file: '不进执行快照：drivers 目录不在路径保护覆盖范围内，判错即删没有兜底 —— 独立禁删面评审过之前不给删。',
        minifilter_after_key_deleted: '不作为删除目标：服务键已删而滤镜仍挂载，删文件不解决问题，需要重启。',
        dead_landing: '本条未进执行快照：服务键窄口子的八道现读判据里至少有一条不成立（详情见 reason 与下方判定依据）。',
        stale_live_service: '不进执行快照：落点还在、服务可能仍在用 —— 窄口子只处理文件已失踪的键。',
        ifeo_debugger: '不进执行快照：IFEO 属微软根，A1 拦着；本区只给说明。',
        ifeo_stale_options: '不建议删除：键本身要留着（删了 Explorer 会重建空键），这一类只是提示。',
        capability_consent_dead_landing: '不进执行快照：ConsentStore 属微软根，A1 拦着；本区只给说明。',
        vendor_product_key_no_landing: '不进执行快照（本阶段）：注册表键的删除链与 A1 窄口子同批评审。'
      };
      return WHY[item.class] || '本区默认只读：这一类没进执行快照，前端画不出勾选框。';
    }
    if (item.deleteCapable === false) return '不允许删除：' + (item.reason || '本链只登记、不删除');
    if (item.class === 'minifilter_after_key_deleted') return '不作为删除目标：键已删而滤镜仍挂载，需要重启，不是删文件能解决的。';
    return '可以删除：勾上之后仍要逐项确认；文件与目录进回收站，注册表项删前先导出 .reg 备份。';
  }

  function openDetail(spec) {
    const item = spec.item;
    if (!item) return;
    if (!window.modal || typeof window.modal.create !== 'function') {
      toast('error', '详情弹窗组件未加载，本次不显示明细');
      return;
    }
    const mountId = 'rsIntroMount-' + Date.now();
    const html = '<div class="rs-detail">'
      + '<div class="rs-detail-block"><div class="rs-detail-h">在哪</div>'
      + '<div class="finder-path-text">' + esc(item.target || '') + '</div>'
      + '<div class="xtable-cell-muted">' + esc(KIND_LABEL[item.kind] || item.kind || '') + (item.class ? ' · ' + esc(item.class) : '') + '</div></div>'
      + '<div class="rs-detail-block"><div class="rs-detail-h">能不能删</div>'
      + '<div class="rs-detail-verdict">' + esc(deletableText(item, spec.from)) + '</div></div>'
      + '<div class="rs-detail-block"><div class="rs-detail-h">为什么</div>'
      + '<div class="xtable-cell-desc">' + esc(item.reason || '（后端没写理由）') + '</div>'
      + contribRows(item) + '</div>'
      + '<div class="rs-detail-block"><div class="rs-detail-h">明细</div>' + detailRows(item.details) + '</div>'
      + '<div class="rs-detail-block"><div class="rs-detail-h">简介</div><div id="' + mountId + '"></div></div>'
      + '</div>';
    const ctrl = window.modal.create({
      id: 'rsDetailModal-' + Date.now(),
      title: item.target || '残留项详情',
      bodyHtml: html,
      bodyClass: 'rs-detail-body'
    });
    // 本地简介 + 联网 AI：复用三模块共用件，本页不再自己拼一遍（§2 转义/组件真源）
    const mount = ctrl.modal && ctrl.modal.querySelector('#' + mountId);
    if (window.intro && mount) {
      window.intro.mountIntroPanel({
        mount: mount,
        scope: 'residue',
        name: String((item.details && (item.details.serviceName || item.details.ownerName)) || item.target || ''),
        company: String((item.details && item.details.publisher) || ''),
        // 外发明细：只有这三键。后端 residue_detail_line 再按白名单筛一遍，
        // 用户名/机器名/卷号/平台整表根本不往这里取（裁定 4 的边界）
        detail: { target: item.target || '', kind: item.kind || '', class: item.class || '' },
        item: item
      });
    }
  }

  function detailSpec(attr) {
    const parts = String(attr || '').split(':');
    if (parts[0] === 'c') {
      const i = Number(parts[1]);
      const it = state.rows[i];
      return it ? { item: it, from: 'chain' } : null;
    }
    if (parts[0] === 'd') {
      const title = parts[1];
      const idx = Number(parts[2]);
      const gi = (state.groupsIndex && state.groupsIndex.get(title)) || [];
      const hit = gi.find(function (x) { return x.idx === idx; });
      return hit ? { item: hit.item, from: 'deep' } : null;
    }
    return null;
  }

  // ==================== 执行（删除选中） ====================

  function updateActionButtons() {
    const any = state.rows.some(function (f) { return f._checked; })
      || state.deepRows.some(function (f) { return f._checked; });
    const clean = el('rsBtnClean');
    if (clean) clean.disabled = !any || state.running;
  }

  async function confirmViaModal(opts) {
    // fail-closed：确认件不在，就当用户没确认 —— 跳过确认直接删是不可接受的
    if (!window.modal || typeof window.modal.confirm !== 'function') {
      toast('error', '确认组件未加载，本次不执行任何删除');
      return false;
    }
    return await window.modal.confirm(opts);
  }

  async function cleanSelected() {
    const picked = state.rows.filter(function (f) { return f._checked; })
      .concat(state.deepRows.filter(function (f) { return f._checked; }));
    if (!picked.length || state.running) return;
    const backup = readBackupPref();
    const ok = await confirmViaModal({
      title: '确认清理残留',
      message: '将删除选中的 ' + picked.length + ' 项残留。文件与目录移入回收站（可还原）；注册表项删除前自动导出备份。'
        + (backup ? '已开启删前备份：选中内容会先打进本机还原包，之后可整批写回原位置。' : ''),
      confirmText: '开始清理',
      cancelText: '取消',
      danger: true,
      dangerHint: '低置信项为名称启发式结果，请确认路径确实属于已卸载的程序再勾选。'
    });
    if (!ok) {
      toast('info', '已取消：本次已发现的 ' + state.rows.length + ' 项候选不会被删除，内容保持原样');
      return;
    }
    state.running = true;
    updateActionButtons();
    el('rsFootHint').textContent = '正在清理残留…';
    try {
      const resp = await window.api.uninstall.residueExecute(
        state.appId,
        picked.map(function (f) { return { kind: f.kind, target: f.target }; }),
        backup
      );
      if (!resp.success) throw new Error(resp.message || '残留清理失败');
      const d = resp.data || {};
      const pack = d.restorePack;
      if (pack && pack.error) {
        toast('error', '还原包写入失败：' + pack.error + '。文件已删除、内容无法还原，回收站仍可查看。');
      }
      const okCount = Number(d.okCount) || 0;
      const failCount = Number(d.failCount) || 0;
      toast(failCount ? 'warning' : 'success',
        failCount ? `残留清理完成：${okCount} 项成功，${failCount} 项失败，详见报告` : `残留清理完成：${okCount} 项已处理`);
      const done = new Set((d.details || []).filter(function (x) { return x.status === 'ok'; }).map(function (x) { return x.kind + '|' + x.target; }));
      state.rows = state.rows.filter(function (f) { return !done.has(f.kind + '|' + f.target); });
      state.scanGroups = state.scanGroups.map(function (g) {
        return Object.assign({}, g, { rows: g.rows.filter(function (f) { return !done.has(f.kind + '|' + f.target); }) });
      });
      renderChains();
      // 深扫区同步摘掉已成功项：直接改报告里的 items（不是改渲染出来的 HTML），
      // 否则「重新扫描」之前那一条还会留在页面上，勾第二次会被快照闸判成过期
      if (state.report && Array.isArray(state.report.groups)) {
        state.report.groups.forEach(function (g) {
          if (Array.isArray(g.items)) {
            g.items = g.items.filter(function (it) { return !done.has(it.kind + '|' + it.target); });
            if (typeof g.count === 'number') g.count = g.items.length;
          }
        });
        state.deepRows = [];
        renderDeep();
      }
      // 失败的文件项（被占用/无权限）才有「重启后删除」出口；目录后端会拒
      const failedFiles = (d.details || [])
        .filter(function (x) { return x.status !== 'ok' && x.kind === 'file'; })
        .map(function (x) { return x.target; });
      updatePendingButtons(failedFiles);
    } catch (e) {
      toast('error', '残留清理失败: ' + (e && e.message ? e.message : e));
    } finally {
      state.running = false;
      updateActionButtons();
      el('rsFootHint').textContent = '勾选来自两个区：三链候选与深扫白名单候选；删除一律回收站优先、逐项确认。';
    }
  }

  // ==================== 重启后删除（PFRO） ====================

  function updatePendingButtons(failedFiles) {
    const addBtn = el('rsBtnPending');
    const revBtn = el('rsBtnPendingRevoke');
    if (addBtn) {
      if (Array.isArray(failedFiles)) state.pendingFailed = failedFiles;
      addBtn.style.display = state.pendingFailed.length ? '' : 'none';
      addBtn.textContent = `重启后删除失败的 ${state.pendingFailed.length} 项…`;
      addBtn.disabled = !state.pendingFailed.length;
    }
    if (revBtn) {
      window.api.uninstall.pendingList().then(function (r) {
        const entries = (r && r.success && r.data && r.data.entries) || [];
        const degraded = !!(r && r.success && r.data && r.data.degraded);
        const n = entries.filter(function (e) { return e.status === 'pending'; }).length;
        if (degraded) {
          // M-6：台账损坏 = 撤回凭据不可信。不能隐藏按钮（那样用户不知道 PFRO 里还挂着），
          // 置灰 + data-tip 说明，与「真的没有待删项」区分开。
          revBtn.style.display = '';
          revBtn.disabled = true;
          revBtn.textContent = '重启后删台账已损坏';
          revBtn.setAttribute('data-tip', '待删清单文件损坏，无法确认哪些条目仍挂起；PFRO 里的登记可能仍会在下次重启时执行。');
        } else {
          revBtn.style.display = n ? '' : 'none';
          revBtn.disabled = !n;
          revBtn.textContent = `撤回重启后删 ${n} 项`;
        }
      }).catch(function () {});
    }
  }

  async function addPendingDeletes() {
    if (!state.pendingFailed.length) return;
    const ok = await confirmViaModal({
      title: '登记重启后删除',
      message: `把 ${state.pendingFailed.length} 个回收站删不掉的文件登记为「下次重启时删除」。这是永久删除：不进回收站、无法还原；重启前可撤回。目录不支持该机制，登记时会被跳过。`,
      confirmText: '登记',
      cancelText: '取消',
      danger: true,
      dangerHint: '将写入系统 PendingFileRenameOperations，重启动作由系统在会话管理器阶段执行，Trim 不参与那一步。'
    });
    if (!ok) return;
    try {
      const resp = await window.api.uninstall.pendingAdd(state.pendingFailed);
      if (!resp.success) throw new Error(resp.message || '登记失败');
      const d = resp.data || {};
      toast(d.added ? 'success' : 'info', d.added
        ? `已登记 ${d.added} 项，将在下次重启时永久删除（重启前可撤回）`
        : '没有新登记项（可能都已登记过或目标已不在）');
      state.pendingFailed = [];
      updatePendingButtons([]);
    } catch (e) {
      toast('error', '登记失败: ' + (e && e.message ? e.message : e));
    }
  }

  async function revokePendingDeletes() {
    const ok = await confirmViaModal({
      title: '撤回重启后删除',
      message: '将把已登记的「重启后删除」条目从系统中摘除：相关文件不会被删除，保持原样。',
      confirmText: '撤回全部',
      cancelText: '取消',
      danger: true
    });
    if (!ok) return;
    try {
      const resp = await window.api.uninstall.pendingRevoke();
      if (!resp.success) throw new Error(resp.message || '撤回失败');
      toast('success', `已撤回 ${(resp.data && resp.data.revoked) || 0} 项登记，相关文件不会被删除`);
      updatePendingButtons([]);
    } catch (e) {
      toast('error', '撤回失败: ' + (e && e.message ? e.message : e));
    }
  }

  async function ignoreOrphanOwner(f) {
    try {
      const resp = await window.api.uninstall.orphanIgnore(f.ownerAppId, f.ownerName || '');
      if (!resp || !resp.success) throw new Error((resp && resp.message) || '写入忽略记录失败');
      toast('success', `已不再提示「${f.ownerName || ''}」的遗留数据`);
      await scanChains();
    } catch (e) {
      toast('error', '忽略失败: ' + (e && e.message ? e.message : e));
    }
  }

  // ==================== 交互装配 ====================

  function onClick(e) {
    // §2.6b：已保护项手风琴的开合（照 finder.js 的 empty-pane 模式，状态记在 state.protOpen）
    const accHead = e.target.closest('.empty-pane-head');
    if (accHead && accHead.closest('[data-rs-acc]')) {
      const pane = accHead.closest('.empty-pane');
      pane.classList.toggle('collapsed');
      const collapsed = pane.classList.contains('collapsed');
      accHead.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      state.protOpen = !collapsed;
      return;
    }
    const ign = e.target.closest('[data-orphan-ignore]');
    if (ign) {
      const target = state.rows[Number(ign.dataset.orphanIgnore)];
      if (target) ignoreOrphanOwner(target);
      return;
    }
    const det = e.target.closest('[data-detail]');
    if (det) {
      const spec = detailSpec(det.dataset.detail);
      if (spec) openDetail(spec);
      else toast('warn', '这条详情已经过期，请重新扫描');
      return;
    }
    const t = e.target.closest('[data-rcheck]');
    if (t) {
      const f = state.rows[Number(t.dataset.rcheck)];
      if (!f || f.deleteCapable === false) return;
      f._checked = !f._checked;
      t.classList.toggle('checked', f._checked);
      t.setAttribute('aria-checked', f._checked ? 'true' : 'false');
      const tr = t.closest('tr');
      if (tr) tr.classList.toggle('finder-row-selected', f._checked);
      updateActionButtons();
      return;
    }
    // 深扫区勾选：只有后端 deleteCapable=true 的那几项画得出勾选框（类白名单在后端）
    const d = e.target.closest('[data-dcheck]');
    if (d) {
      const it = state.deepRows[Number(d.dataset.dcheck)];
      if (!it) return;
      it._checked = !it._checked;
      d.classList.toggle('checked', it._checked);
      d.setAttribute('aria-checked', it._checked ? 'true' : 'false');
      const tr = d.closest('tr');
      if (tr) tr.classList.toggle('finder-row-selected', it._checked);
      updateActionButtons();
    }
  }

  // 勾选框是 span 不是 input：键盘可达性要自己补（AGENTS §2，行上「查残留」同理）。
  // 两个区的勾选框都要覆盖：深扫区的 data-dcheck 也是 tabindex=0 的 span，
  // 早先只处理 data-rcheck，Tab 过去按空格没有任何反应。
  function onKeydown(e) {
    if (e.key !== ' ' && e.key !== 'Enter') return;
    const t = e.target.closest && e.target.closest('[data-rcheck], [data-dcheck]');
    if (!t) return;
    e.preventDefault();
    onClick({ target: t, });
  }

  // 事件委托的宿主是**两个区各自的容器**，不是一个整页 `#rsBody`：本窗由主窗内联面板
  // 搬进副窗时改名成了 rsChainBody / rsDeepBody，而绑定行还写着旧 id —— 在 null 上取
  // addEventListener 抛 TypeError，DOMContentLoaded 因此中断在 scanAll() 之前，
  // 真机症状是界面永远停在「正在扫描三类残留…」（2026-10-05 用户截图坐实）。
  // 所以绑定一律走下面的 on()：缺件只降级成控制台告警，绝不许把整条初始化带崩。
  function on(id, type, handler) {
    const node = el(id);
    if (!node) {
      console.warn('[residue-window] 缺少元素 #' + id + '，' + type + ' 未绑定');
      return false;
    }
    node.addEventListener(type, handler);
    return true;
  }

  async function scanAll() {
    // scanChains 体内容错比 scanDeep 弱（后者自带 try/catch）：三链里任何一处抛错
    // —— 包括渲染阶段的抛错 —— 都会把界面留在「正在扫描三类残留…」，而原因只在控制台里，
    // 用户和日志都看不到（2026-10-05 真机就是这个形态）。这里补一道收口，把抛错变成可见文案。
    await Promise.all([
      scanChains().catch(function (e) {
        const msg = String((e && e.message) || e);
        const box = el('rsChainBody');
        if (box) box.innerHTML = '<div class="finder-empty">三链扫描中断：' + esc(msg) + '</div>';
        toast('error', '残留扫描出错：' + msg);
      }),
      scanDeep(),
    ]);
  }

  document.addEventListener('DOMContentLoaded', function () {
    state.appId = targetFromSearch();
    for (const host of ['rsChainBody', 'rsDeepBody']) {
      on(host, 'click', onClick);
      on(host, 'keydown', onKeydown);
    }
    on('rsRescanBtn', 'click', scanAll);
    on('rsBtnClean', 'click', cleanSelected);
    on('rsBtnPending', 'click', addPendingDeletes);
    on('rsBtnPendingRevoke', 'click', revokePendingDeletes);
    on('rsCloseBtn', 'click', function () {
      window.api.residueWindow.closeWindow().catch(function () { toast('warn', '关闭窗口失败，请手动关闭'); });
    });
    on('rsBackupToggle', 'change', function (e) { writeBackupPref(e.target.checked); });
    const toggle = el('rsBackupToggle');
    if (toggle) toggle.checked = readBackupPref();
    on('rsSearch', 'input', function (e) {
      state.filter = e.target.value || '';
      renderChains();
      renderDeep();
    });
    document.addEventListener('keydown', function (e) {
      // modal.js 自己管 Esc（requestClose）；有弹窗在台上时这扇窗不跟着关
      if (e.key === 'Escape' && !document.querySelector('.usage-backdrop')) {
        window.api.residueWindow.closeWindow().catch(function () {});
      }
    });
    // 副窗已经开着、主窗又点了一次「查残留」：目标从事件进来，重扫覆盖旧集合
    if (window.api.residueWindow.onTarget) {
      window.api.residueWindow.onTarget(function (payload) {
        state.appId = String(payload || '');
        scanAll();
      });
    }
    scanAll();
  });
})();
