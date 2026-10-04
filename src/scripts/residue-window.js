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
    uninstall: '失效卸载项（可删该注册表键）',
    appPaths: '失效 App Paths（可删该注册表键）',
  };

  // appId 从哪来：主窗卸载成功后经 URL query 带进来（后端开窗前先过取值闸）；
  // 副窗已开着时同一份值走 `residue:target` 事件。两处拿到的都还要再过一次
  // 执行侧的 `app_id 格式错误` 闸 —— 这里的前置判断只为少发一次无谓请求，不当安全边界用。
  const state = {
    appId: '',
    rows: [],            // 三链候选（扁平数组，勾选按全局下标寻址）
    scanGroups: [],
    report: null,        // 深扫报告
    filter: '',
    pendingFailed: [],
    running: false,
    scanning: false,
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
    box.innerHTML = '<div class="finder-empty">正在扫描三类残留（规则库 / 失效登记 / 卸载记录）…</div>';
    const app = state.appId;
    const fail = (e) => ({ success: false, message: String((e && e.message) || e) });
    const [rApp, rDead, rOrphan] = await Promise.all([
      app ? window.api.uninstall.residueScan(app).catch(fail) : Promise.resolve(null),
      window.api.uninstall.deadScan().catch(fail),
      window.api.uninstall.orphanScan().catch(fail),
    ]);
    const groups = [];
    if (!app) {
      groups.push({ title: '程序残留（规则库）', rows: [], hint: '未选中程序。从卸载页某一行的「查残留」进来，就会带上它的规则库残留。' });
    } else if (rApp && rApp.success) {
      const name = (rApp.data && rApp.data.appName) || '';
      groups.push({ title: `程序残留 · ${name}（规则库命中）`, rows: (rApp.data && rApp.data.findings) || [] });
    } else {
      groups.push({ title: '程序残留（规则库）', rows: [], hint: ((rApp && rApp.message) || '本组扫描失败') });
    }
    if (rDead && rDead.success) {
      groups.push({ title: '失效残留 · 全机（卸载项与 App Paths 记着的落点已不存在）', rows: (rDead.data && rDead.data.findings) || [], byClass: true });
    } else {
      groups.push({ title: '失效残留 · 全机', rows: [], hint: ((rDead && rDead.message) || '本组扫描失败') });
    }
    if (rOrphan && rOrphan.success) {
      groups.push({ title: '卸载遗留 · 按本机卸载记录（应用数据目录与卸后新增的厂商配置键）', rows: (rOrphan.data && rOrphan.data.findings) || [] });
    } else {
      // 这一组拒绝扫描是**正确行为**（档案为空时拿空集会被读成"这台机器没有遗留"）
      groups.push({ title: '卸载遗留 · 按本机卸载记录', rows: [], hint: ((rOrphan && rOrphan.message) || '本组未执行') });
    }
    state.scanGroups = groups;
    state.rows = groups.reduce(function (acc, g) { return acc.concat(g.rows); }, []);
    // 勾选初值在渲染前定好：只展示不给删的行永远不该被勾上
    state.rows.forEach(function (f) { f._checked = f.deleteCapable !== false && !!f.defaultChecked; });
    renderChains();
    updateActionButtons();
    state.scanning = false;
    const n = state.rows.length;
    const notes = (rDead && rDead.success && rDead.data.notes && rDead.data.notes.length) ? rDead.data.notes[0] : '';
    toast(n ? 'info' : 'success', n ? `三链候选共 ${n} 项，一律未自动勾选，请逐项确认` : (notes || '三类扫描都没有发现残留'));
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
      toast('info', '深扫完成（这一区只出报告，不参与删除）');
    } catch (e) {
      box.innerHTML = '<div class="finder-empty">深扫失败：' + esc(e && e.message ? e.message : e) + '</div>';
      toast('error', '深扫失败：' + (e && e.message ? e.message : e));
    }
  }

  function deepTableHtml(title, items, kind) {
    const head = '<div class="finder-group-header" style="margin-top:14px"><span>' + esc(title) + ' · ' + items.length + ' 项</span></div>';
    if (!items.length) return head + '<div class="finder-empty">' + esc('本组没有候选。') + '</div>';
    const rows = items.map(function (it, idx) {
      // 只读区的断言：后端不该给出任何「默认选中」的候选（它没有删除入口，勾选态无处可去）
      const drift = it.defaultChecked === true ? ' <span class="badge badge-warn">形态漂移：只读区不该有默认勾选项</span>' : '';
      const gi = state.groupsIndex.get(title) || [];
      gi.push({ item: it, kind: kind, idx: idx });
      state.groupsIndex.set(title, gi);
      return '<tr>'
        + '<td><div class="xtable-cell-path">' + esc(it.target) + '</div>'
        + '<div class="xtable-cell-muted">' + esc(it.reason || '') + drift + '</div></td>'
        + '<td style="width:96px"><button class="btn btn-secondary rs-mini-btn" data-detail="d:' + esc(title) + ':' + idx + '" data-tip="查看落点、可否删除与判定依据">点击查看</button></td>'
        + '</tr>';
    }).join('');
    return head + '<table class="finder-table"><thead><tr><th>目标</th><th style="width:96px">详情</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  function summaryHtml(r) {
    const s = r.scanned || {};
    const total = (r.groups || []).reduce(function (n, g) { return n + (g.count || 0); }, 0);
    const platform = r.platforms || {};
    const parts = [
      '候选合计 ' + total + ' 项',
      '已保护 ' + (r.protectedCount || 0) + ' 项（在库 / 在用 / 微软签名）',
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
      return deepTableHtml(g.title + '（' + g.id + '）', (g.items || []).filter(passes), 'group');
    }).join('');
    const protectedItems = (r.protected || []).filter(passes);
    // 「有保护的不允许删除」就在这一栏：只给说明，不给勾选、不给按钮
    const protHtml = protectedItems.length ? deepTableHtml('已保护项（不允许删除，只说明为什么）', protectedItems, 'protected') : '';
    body.innerHTML = groups + protHtml;
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

  // 可否删：三链看 deleteCapable，深扫区本轮一律只读（后端不写快照，勾了也执行不了）
  function deletableText(item, from) {
    if (from === 'deep') {
      return '本轮不提供删除：这一区的结果**没有写进执行快照**，后端拿它当报告用。'
        + '（深扫七器进执行链是方案 §4 的第二期，先把判据与快照形态评审过再开。）';
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
    const any = state.rows.some(function (f) { return f._checked; });
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
    const picked = state.rows.filter(function (f) { return f._checked; });
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
        toast('error', '还原包写入失败：' + pack.error + '（文件已删除，内容无法还原，回收站仍可查看）');
      }
      const okCount = Number(d.okCount) || 0;
      const failCount = Number(d.failCount) || 0;
      toast(failCount ? 'warning' : 'success',
        failCount ? `残留清理完成：${okCount} 项成功，${failCount} 项失败（详见报告）` : `残留清理完成：${okCount} 项已处理`);
      const done = new Set((d.details || []).filter(function (x) { return x.status === 'ok'; }).map(function (x) { return x.kind + '|' + x.target; }));
      state.rows = state.rows.filter(function (f) { return !done.has(f.kind + '|' + f.target); });
      state.scanGroups = state.scanGroups.map(function (g) {
        return Object.assign({}, g, { rows: g.rows.filter(function (f) { return !done.has(f.kind + '|' + f.target); }) });
      });
      renderChains();
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
      el('rsFootHint').textContent = '三链区可勾选删除；深扫区只出报告，不改动本机任何东西。';
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
          revBtn.textContent = `撤回重启后删（${n} 项）`;
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
    if (!t) return;
    const f = state.rows[Number(t.dataset.rcheck)];
    if (!f || f.deleteCapable === false) return;
    f._checked = !f._checked;
    t.classList.toggle('checked', f._checked);
    t.setAttribute('aria-checked', f._checked ? 'true' : 'false');
    const tr = t.closest('tr');
    if (tr) tr.classList.toggle('finder-row-selected', f._checked);
    updateActionButtons();
  }

  // 勾选框是 span 不是 input：键盘可达性要自己补（AGENTS §2，行上「查残留」同理）
  function onKeydown(e) {
    if (e.key !== ' ' && e.key !== 'Enter') return;
    const t = e.target.closest && e.target.closest('[data-rcheck]');
    if (!t) return;
    e.preventDefault();
    onClick({ target: t, });
  }

  async function scanAll() {
    await Promise.all([scanChains(), scanDeep()]);
  }

  document.addEventListener('DOMContentLoaded', function () {
    state.appId = targetFromSearch();
    el('rsBody').addEventListener('click', onClick);
    el('rsBody').addEventListener('keydown', onKeydown);
    el('rsRescanBtn').addEventListener('click', scanAll);
    el('rsBtnClean').addEventListener('click', cleanSelected);
    el('rsBtnPending').addEventListener('click', addPendingDeletes);
    el('rsBtnPendingRevoke').addEventListener('click', revokePendingDeletes);
    el('rsCloseBtn').addEventListener('click', function () {
      window.api.residueWindow.closeWindow().catch(function () { toast('warn', '关闭窗口失败，请手动关闭'); });
    });
    const toggle = el('rsBackupToggle');
    toggle.checked = readBackupPref();
    toggle.addEventListener('change', function () { writeBackupPref(toggle.checked); });
    el('rsSearch').addEventListener('input', function (e) {
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
