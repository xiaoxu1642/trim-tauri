// residue-window.js - 「应用卸载残留扫描」副窗口（v0.7.0 起由「卸载完成后自动弹出」唯一唤起）。
//
// 只展示**该应用**的四类残留：服务残留 / 驱动残留 / 注册表残留 / 文件·文件夹残留。
// 四类之外的所有扫描分组（机-wide 失效登记、卸载遗留档案、七个深扫器报告）已整条退役——
// 后端 `uninstall:residue-scan` 只回这四类，每条候选带一个 `bucket` 字段决定分组。
//
// 勾选 → 删除仍走 `uninstall:residue-execute`：后端按本窗 label 分槽的执行快照是唯一闸门，
// 服务/驱动类候选会被 `service_key_delete_block_reason` 的现读判据挡在删除链外（预期行为）。
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
  // D2（v4 审查）：读失败/坏值一律走「未开启」方向并留痕（控制台 + 应用日志，log_write
  // 五窗可调）。误拨到「开」的代价只是删除前多一次打包，方向本身安全；留痕是为了能解释
  // 「开关为什么回到关」——静默降级正是这条被记下来的原因。
  function readBackupPref() {
    let raw = null;
    try { raw = localStorage.getItem(BACKUP_PREF_KEY); }
    catch (e) {
      console.warn('[Trim] 备份开关偏好读取失败，已按未开启处理:', e);
      try { window.api?.log?.write?.('warn', '残留副窗：备份开关偏好读取失败，已按未开启处理'); } catch (_) { /* 日志通道不可用则降级到控制台 */ }
      return false;
    }
    if (raw === '1') return true;
    if (raw !== null && raw !== '' && raw !== '0') {
      console.warn(`[Trim] 备份开关偏好值异常（${raw}），已按未开启处理`);
      try { window.api?.log?.write?.('warn', '残留副窗：备份开关偏好值异常，已按未开启处理'); } catch (_) { /* 同上 */ }
    }
    return false;
  }
  function writeBackupPref(on) {
    try { localStorage.setItem(BACKUP_PREF_KEY, on ? '1' : '0'); }
    catch (e) {
      console.warn('[Trim] 备份开关偏好写入失败:', e);
      try { window.api?.log?.write?.('warn', '残留副窗：备份开关偏好写入失败，本次选择下次启动会丢失'); } catch (_) { /* 同上 */ }
    }
  }

  const CONF_LABEL = { high: '高置信', medium: '中置信', low: '低置信（建议人工核对）' };
  const KIND_LABEL = { reg_key: '注册表项', reg_value: '注册表值', folder: '目录', file: '文件', shortcut: '快捷方式' };

  // 四类固定顺序：后端每条候选的 `bucket` 只取这四个值（判据在 residue.rs）
  const BUCKETS = [
    { key: 'service', title: '服务残留' },
    { key: 'driver', title: '驱动残留' },
    { key: 'registry', title: '注册表残留' },
    { key: 'file', title: '文件·文件夹残留' },
  ];

  // appId 从哪来：主窗卸载成功后经 URL query 带进来（后端开窗前先过取值闸）；
  // 副窗已开着时同一份值走 `residue:target` 事件。两处拿到的都还要再过一次
  // 执行侧的 `app_id 格式错误` 闸 —— 这里的前置判断只为少发一次无谓请求，不当安全边界用。
  const state = {
    appId: '',
    rows: [],        // 四类候选（扁平数组，勾选按全局下标寻址）
    notes: [],
    scanned: false,
    filter: '',
    pendingFailed: [],
    running: false,
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
    const hay = [item.target, item.class, item.reason, item.kind, d.serviceName, d.image, d.imagePath, d.landing]
      .filter(function (v) { return typeof v === 'string' && v; })
      .join('\n')
      .toLowerCase();
    return hay.indexOf(q) >= 0;
  }

  // ==================== 四类候选 ====================

  async function scanResidue() {
    const box = el('rsChainBody');
    box.innerHTML = '<div class="finder-empty">正在扫描该应用的四类残留…</div>';
    const app = state.appId;
    if (!app) {
      state.rows = [];
      state.notes = [];
      state.scanned = false;
      box.innerHTML = '<div class="finder-empty">未选中程序。本窗只由「卸载完成后自动弹出」唤起，会带上刚卸载的那个应用。</div>';
      updateActionButtons();
      return;
    }
    let res;
    try {
      res = await window.api.uninstall.residueScan(app);
    } catch (e) {
      res = { success: false, message: String((e && e.message) || e) };
    }
    if (!res || !res.success) {
      state.rows = [];
      state.notes = [];
      state.scanned = false;
      box.innerHTML = '<div class="finder-empty">残留扫描失败：' + esc((res && res.message) || '本组扫描失败') + '</div>';
      toast('error', '残留扫描失败：' + ((res && res.message) || '未知错误'));
      updateActionButtons();
      return;
    }
    state.rows = (res.data && res.data.findings) || [];
    state.notes = (res.data && res.data.notes) || [];
    state.scanned = true;
    // 勾选初值在渲染前定好：只展示不给删的行永远不该被勾上。
    // 2026-10-06 用户裁定：进残留列表后可直接执行删除 ⇒ 后端判可删的候选一律默认勾上
    // （原口径「除规则库高置信项外不自动勾选」废止）；删除仍走逐批确认，保护项不给勾。
    state.rows.forEach(function (f) { f._checked = f.deleteCapable !== false; });
    renderChains();
    updateActionButtons();
    const n = state.rows.length;
    toast(n ? 'info' : 'success', n
      ? `该应用共 ${n} 项残留候选，可删项已默认勾选，确认后即可执行删除`
      : (state.notes[0] || '四类扫描都没有发现残留'));
  }

  function tableHtml(rows) {
    let h = '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>目标</th><th style="width:110px">置信度</th><th style="width:96px">详情</th></tr></thead><tbody>';
    for (const f of rows) {
      const i = state.rows.indexOf(f);
      const cell = f.deleteCapable === false
        ? '<span class="finder-name-text" style="opacity:.5" data-tip="本链只登记、不删除">—</span>'
        : '<span class="checkbox' + (f._checked ? ' checked' : '') + '" data-rcheck="' + i + '" tabindex="0" role="checkbox" aria-checked="' + (f._checked ? 'true' : 'false') + '"></span>';
      h += '<tr class="' + (f._checked ? 'finder-row-selected' : '') + '">'
        + '<td>' + cell + '</td>'
        + '<td><div class="finder-cell"><span class="finder-path-text">' + esc(f.target) + '</span></div>'
        + '<div class="xtable-cell-muted">' + esc(f.reason || '') + '</div></td>'
        + '<td class="finder-col-size"><span class="finder-name-text" style="opacity:.75">' + esc(CONF_LABEL[f.confidence] || f.confidence || '—') + '</span></td>'
        // 行上只留一行结论，"在哪 / 能不能删 / 为什么"三点全在详情里（用户 2026-10-05：信息过于冗余）
        + '<td class="finder-col-size"><button class="btn btn-secondary rs-mini-btn" data-detail="c:' + i + '" data-tip="查看落点、可否删除与判定依据">点击查看</button></td>'
        + '</tr>';
    }
    return h + '</tbody></table>';
  }

  function bucketHtml(b) {
    const all = state.rows.filter(function (f) { return (f.bucket || '') === b.key; });
    const shown = all.filter(passes);
    const head = '<div class="finder-group-header" style="margin-top:14px"><span>' + esc(b.title) + ' · ' + all.length + ' 项</span></div>';
    if (!all.length) return head + '<div class="finder-empty">本组没有候选。</div>';
    if (!shown.length) return head + '<div class="finder-empty">' + esc('本组有 ' + all.length + ' 项，但没有匹配当前搜索的。') + '</div>';
    return head + tableHtml(shown);
  }

  function renderChains() {
    const box = el('rsChainBody');
    if (!state.scanned) {
      box.innerHTML = '<div class="finder-empty">还没扫。点上方「重新扫描」扫描该应用的四类残留。</div>';
      return;
    }
    if (!state.rows.length) {
      const note = state.notes[0] || '四类扫描都没有发现残留。';
      box.innerHTML = '<div class="finder-empty">' + esc(note) + '</div>' + BUCKETS.map(bucketHtml).join('');
      return;
    }
    box.innerHTML = BUCKETS.map(bucketHtml).join('');
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
      publisher: '发行商', kind: '形状', note: '备注', platform: '平台', target: '目标'
    };
    const keys = Object.keys(d || {});
    if (!keys.length) return '<div class="xtable-cell-muted">这条没有附加明细。</div>';
    return '<table class="finder-table"><tbody>' + keys.map(function (k) {
      const v = d[k];
      const shown = Array.isArray(v) ? v.join('、') : (typeof v === 'boolean' ? (v ? '是' : '否') : String(v));
      return '<tr><td style="width:150px"><span class="finder-name-text" style="opacity:.7">' + esc(LABELS[k] || k) + '</span></td><td><span class="finder-path-text">' + esc(shown) + '</span></td></tr>';
    }).join('') + '</tbody></table>';
  }

  // 可否删：只看后端回带的 deleteCapable（判据在扫描/执行侧，前端不再自己判一遍，§5.16）。
  // 服务与驱动类候选会被执行侧 `service_key_delete_block_reason` 的现读判据挡住（不给删），
  // 这里只负责把「为什么不给删」说清楚，判据不在这一层。
  function deletableText(item) {
    if (item.deleteCapable === false) return '不允许删除：' + (item.reason || '本链只登记、不删除');
    if (item.bucket === 'service' || item.bucket === 'driver') {
      return '可以删除：服务/驱动键删除由八道现读判据把住（落点已失踪、不在系统目录、非内核驱动、'
        + '非 boot/system 启动、无依赖声明、不在反作弊名单）；驱动类通常会被挡下（本类候选仍列出供你判断）。'
        + '删除前会先整键导出 .reg 备份；还原是把键加回去，不恢复运行状态，可能需重启才生效。已提权才允许执行。';
    }
    return '可以删除：勾上之后仍要逐项确认；文件与目录进回收站，注册表项删前先导出 .reg 备份。';
  }

  function openDetail(item) {
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
      + '<div class="rs-detail-verdict">' + esc(deletableText(item)) + '</div></div>'
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
        name: String((item.details && item.details.serviceName) || item.target || ''),
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
      return it || null;
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
      message: '将删除选中的 ' + picked.length + ' 项残留。文件与目录移入回收站（可还原）；注册表项删除前自动导出备份。',
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
      const okCount = Number(d.okCount) || 0;
      const failCount = Number(d.failCount) || 0;
      toast(failCount ? 'warning' : 'success',
        failCount ? `残留清理完成：${okCount} 项成功，${failCount} 项失败，详见报告` : `残留清理完成：${okCount} 项已处理`);
      const done = new Set((d.details || []).filter(function (x) { return x.status === 'ok'; }).map(function (x) { return x.kind + '|' + x.target; }));
      state.rows = state.rows.filter(function (f) { return !done.has(f.kind + '|' + f.target); });
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
      el('rsFootHint').textContent = '勾选后删除一律回收站优先、逐项确认；能勾的只有后端放进执行快照的四类候选。';
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

  // ==================== 交互装配 ====================

  function onClick(e) {
    const det = e.target.closest('[data-detail]');
    if (det) {
      const item = detailSpec(det.dataset.detail);
      if (item) openDetail(item);
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
    }
  }

  // 勾选框是 span 不是 input：键盘可达性要自己补（AGENTS §2）
  function onKeydown(e) {
    if (e.key !== ' ' && e.key !== 'Enter') return;
    const t = e.target.closest && e.target.closest('[data-rcheck]');
    if (!t) return;
    e.preventDefault();
    onClick({ target: t });
  }

  // 事件委托的宿主是 #rsChainBody；缺件只降级成控制台告警，绝不许把整条初始化带崩
  // （2026-10-05 真机：在 null 上取 addEventListener 抛错，界面永远停在「正在扫描」）。
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
    // scanResidue 内部已把失败变成可见文案；这里再收一道口，防渲染阶段的抛错把界面留在扫描中。
    await scanResidue().catch(function (e) {
      const msg = String((e && e.message) || e);
      const box = el('rsChainBody');
      if (box) box.innerHTML = '<div class="finder-empty">残留扫描中断：' + esc(msg) + '</div>';
      toast('error', '残留扫描出错：' + msg);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    state.appId = targetFromSearch();
    on('rsChainBody', 'click', onClick);
    on('rsChainBody', 'keydown', onKeydown);
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
    });
    document.addEventListener('keydown', function (e) {
      // modal.js 自己管 Esc（requestClose）；有弹窗在台上时这扇窗不跟着关
      if (e.key === 'Escape' && !document.querySelector('.usage-backdrop')) {
        window.api.residueWindow.closeWindow().catch(function () {});
      }
    });
    // 副窗已经开着、主窗又完成一次卸载：目标从事件进来，重扫覆盖旧集合
    if (window.api.residueWindow.onTarget) {
      window.api.residueWindow.onTarget(function (payload) {
        state.appId = String(payload || '');
        scanAll();
      });
    }
    scanAll();
  });
})();
