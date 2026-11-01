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
  function toast(type, message) {
    // F4a1-L12：sub-toast.js 缺席时旧实现全窗零反馈（与本窗「确认件缺席即 fail-closed
    // 且明示」的纪律不对称）。组件在就按组件播；不在就把该说的话写进页内提示行。
    if (window.subToast?.hintLine) {
      window.subToast.hintLine('rsGlobalHint', type, message);
      return;
    }
    console.error('[residue-window] sub-toast 未加载，提示仅写入页内提示行：' + type + ' · ' + message);
    const hint = el('rsGlobalHint');
    if (hint) hint.textContent = String(message == null ? '' : message);
  }

  // P2-13（2026-10-09）：真源迁后端 settings.json 的 `residueBackupPack` 键（AGENTS §0.2：
  // 配置真源在 %APPDATA%，localStorage 只是镜像）。本窗与主窗共享同一 localStorage，
  // 但真源本应是应用私有配置——一次存储清空就把用户打开的「删除前备份」拨回关闭
  //（误拨到关 = 少一层保护）。localStorage 降级为同步初值 + 迁移来源 + 镜像。
  // D2（v4 审查）：读失败/坏值一律走「未开启」方向并留痕（控制台 + 应用日志，log_write
  // 对 engine::guard::APP_WINDOWS 的全部 label 放行）。误拨到「开」的代价只是删除前多一次
  // 打包，方向本身安全；留痕是为了能解释「开关为什么回到关」——静默降级正是这条被记下来的
  // 原因。条数不写在这里（自然语言里的窗口数会随 APP_WINDOWS 增删腐烂）。
  const BACKUP_PREF_KEY = 'trim.residue.backupPack';
  const BACKUP_PREF_BACKEND_KEY = 'residueBackupPack';
  let backupPref = readLsBackupPref();
  let backupPrefDirty = false;

  function readLsBackupPref() {
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
  function readBackupPref() { return backupPref === true; }
  function writeBackupPref(on) {
    backupPref = on === true;
    backupPrefDirty = true;
    try { localStorage.setItem(BACKUP_PREF_KEY, backupPref ? '1' : '0'); }
    catch (e) { console.warn('[Trim] 备份开关镜像写入失败（真源仍写后端）:', e); }
    try {
      window.api?.settings?.setPref?.(BACKUP_PREF_BACKEND_KEY, backupPref)?.catch?.((e) => {
        console.warn('[Trim] 备份开关偏好写入配置失败:', e);
        try { window.api?.log?.write?.('warn', '残留副窗：备份开关偏好写入配置失败，本次选择下次启动可能丢失'); } catch (_) { /* 同上 */ }
      });
    } catch (e) { console.warn('[Trim] 备份开关偏好写入配置异常:', e); }
  }

  // 后端真源回读：boolean ⇒ 采纳并同步勾选框；非 boolean（未设置/坏值）⇒ 把本地现值
  // 一次性迁移上去。backupPrefDirty 时跳过采纳（读回的是写入前的旧值）。
  (async function syncBackupPref() {
    try {
      const resp = await window.api?.settings?.getPrefs?.();
      if (!resp || !resp.success || backupPrefDirty) return;
      const v = resp.data?.[BACKUP_PREF_BACKEND_KEY];
      if (typeof v === 'boolean') {
        if (v !== backupPref) {
          backupPref = v;
          try { localStorage.setItem(BACKUP_PREF_KEY, v ? '1' : '0'); } catch (e) { /* 镜像写失败不影响（真源已就位） */ }
          const t = el('rsBackupToggle');
          if (t) t.checked = v;
        }
      } else {
        writeBackupPref(backupPref); // 迁移：后端没有值，把本地现值推上去
      }
    } catch (e) { /* 真源不可用按本地镜像工作 */ }
  })();

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
    running: false,
  };
  // F4a1-L08：扫描世代号。连点「重新扫描」或主窗再推 residue:target 时，先发的旧回执
  // 可能后到；回写前比对世代号，过期回执直接丢弃，避免 rows/appId 错配。
  let scanGen = 0;

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
    const gen = ++scanGen;
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
    if (gen !== scanGen) return; // 已有更新的扫描发起：旧回执作废
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
    // 勾选初值 = 后端每条候选的 `defaultChecked`（生产者只在 residue.rs / residue_update.rs）。
    // 2026-10-15 裁定（方案 J2）：废止 2026-10-06 的「后端判可删一律默认勾上」——低置信启发式、
    // 侧痕、服务/驱动键、学习库命中这几类后端刻意给 false，交人工逐项勾选；删除仍走逐批确认。
    state.rows.forEach(function (f) { f._checked = f.defaultChecked === true; });
    renderChains();
    updateActionButtons();
    const n = state.rows.length;
    toast(n ? 'info' : 'success', n
      ? `该应用共 ${n} 项残留候选，已按默认状态预勾选，未勾上的需手动勾选才会删`
      : (state.notes[0] || '四类扫描都没有发现残留'));
  }

  function tableHtml(rows) {
    let h = '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>目标</th><th style="width:110px">置信度</th><th style="width:96px">详情</th></tr></thead><tbody>';
    for (const f of rows) {
      const i = state.rows.indexOf(f);
      // F4a1-L04：role=checkbox 必须有可访问名——读屏落到这枚 span 时只报「复选框，未选中」
      // 说不出是哪一项（目标路径是这一行唯一的身份），故把 target 显式给 aria-label。
      const cell = '<span class="checkbox' + (f._checked ? ' checked' : '') + '" data-rcheck="' + i + '" tabindex="0" role="checkbox" aria-checked="' + (f._checked ? 'true' : 'false') + '" aria-label="' + esc(f.target) + '"></span>';
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

  // 能不能删由执行侧现读判定（`classify_residue_op`），前端不判、也不展示后端可删结论
  // （deleteCapable 契约已按 2026-10-15 裁定摘除）；这里只负责说清「删的时候会发生什么」。
  function deletableText(item) {
    if (item.bucket === 'service' || item.bucket === 'driver') {
      return '能不能删要执行时现读判定：服务/驱动键删除由八道现读判据把住（落点已失踪、不在系统目录、非内核驱动、'
        + '非 boot/system 启动、无依赖声明、不在反作弊名单）；驱动类通常会被挡下（本类候选仍列出供你判断）。'
        + '删除前会先整键导出 .reg 备份；还原是把键加回去，不恢复运行状态，可能需重启才生效。已提权才允许执行。';
    }
    return '勾上之后仍要逐项确认；文件与目录进回收站，注册表项删前先导出 .reg 备份。能不能删以执行时现读判定为准。';
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
    // X-4（方案 J14）：取数面 = 当前**可见**的勾选项（过 passes 过滤）。_checked 语义不动——
    // 被搜索隐藏的行勾选态保留，清空搜索后回来仍在；未搜索时 passes 恒 true，与旧行为等价。
    const picked = state.rows.filter(passes).filter(function (f) { return f._checked; });
    if (state.running) return;
    if (!picked.length) {
      // 按钮按全窗勾选判（updateActionButtons 不改），搜索把勾选项全藏起来时按钮仍可点；
      // 早退前给一句可见反馈，防「点了没反应」（其余场景按钮本就是禁用的）
      if (state.filter.trim()) toast('info', '当前搜索结果内没有勾选项');
      return;
    }
    const backup = readBackupPref();
    // F4a1-M09：红/黄色档的确认按钮取明确的动作动词，而不是无脑回车能滑过去的「确定」。
    // 本窗三处按动作命名：清理与登记用「仍然清理 / 仍然登记」，撤回是安全方向、走「撤回全部」。
    // 主窗同族确认里既有「仍然X」也有沿用动作名的档位（口径未完全统一，不在本窗单方改动）；
    // 档位本身不变：残留删除是批量且注册表侧不可逐项撤销，仍走红色。
    // F4a1-M04：确认件的 await 必须在 try 内。modal.confirm 的 Promise 执行器里同步调 create()，
    // 装配抛错（focusTrap/节点/样式异常）即整条 Promise reject；旧写法三处 await 都在 try 之外，
    // reject 只能落到全局 unhandledrejection（ds.js 只写日志、不弹 toast）⇒ 用户看到「点了没反应」。
    // catch 按 fail-closed 收口：确认件异常一律当「未确认」，本次条目不删。
    let ok = false;
    try {
      ok = await confirmViaModal({
        title: '确认清理残留',
        message: '将删除选中的 ' + picked.length + ' 项残留。文件与目录移入回收站（可还原）；注册表项删除前自动导出备份。',
        confirmText: '仍然清理',
        cancelText: '取消',
        danger: true,
        dangerHint: '低置信项为名称启发式结果，请确认路径确实属于已卸载的程序再勾选。'
      });
    } catch (e) {
      toast('error', '确认组件异常，本次不执行任何清理');
      return;
    }
    if (!ok) {
      toast('info', '已取消：本次已发现的 ' + state.rows.length + ' 项候选不会被删除，内容保持原样');
      return;
    }
    state.running = true;
    try {
      updateActionButtons();
      const hint = el('rsFootHint');
      if (hint) hint.textContent = '正在清理残留…';
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
      // 2026-11-02 用户裁定：登记重启后删除的入口退役，本窗只剩撤回按钮的显隐刷新
      updatePendingButtons();
    } catch (e) {
      toast('error', '残留清理失败: ' + (e && e.message ? e.message : e));
    } finally {
      state.running = false;
      updateActionButtons();
      const hint = el('rsFootHint');
      if (hint) hint.textContent = '勾选后删除一律回收站优先、逐项确认；能勾的只有后端放进执行快照的四类候选。';
    }
  }

  // ==================== 重启后删除（PFRO） ====================

  // 撤回按钮的基线 data-tip 快照（见 updatePendingButtons 的说明）；null = 尚未取过
  let revBtnBaselineTip = null;

  /// 按待删清单回执刷「撤回重启后删」按钮的显隐与计数（2026-11-02 起本域只保留
  /// 查看/撤回；登记入口已退役，故本函数不再接手任何待登记集合）。
  function updatePendingButtons() {
    const revBtn = el('rsBtnPendingRevoke');
    // 撤回按钮的基线提示以 HTML 为真源，只在首次（任何降级态覆盖之前）取一次：
    // 下面 degraded / 读取失败两支会改写 data-tip，恢复正常时必须还原，否则用户看到的是过期原因。
    if (revBtnBaselineTip === null && revBtn) revBtnBaselineTip = revBtn.getAttribute('data-tip') || '';
    if (revBtn && window.api?.uninstall?.pendingList) {
      window.api.uninstall.pendingList().then(function (r) {
        const entries = (r && r.success && r.data && r.data.entries) || [];
        const degraded = !!(r && r.success && r.data && r.data.degraded);
        // R2a-U01（B 方案）：orphanSource 对补行（PFRO 挂着但台账无凭据）不在
        // 「撤回全部」的摘除集合里——按钮计数与显隐只数可撤的登记项。
        const n = entries.filter(function (e) { return e.status === 'pending' && !e.orphanSource; }).length;
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
          if (revBtnBaselineTip) revBtn.setAttribute('data-tip', revBtnBaselineTip);
          else revBtn.removeAttribute('data-tip');
        }
      }).catch(function (e) {
        // F4a1-M04：待删清单读不到就不能装成「没有待删项」（旧写法空 catch，按钮停在上一轮的
        // 显隐）。与上面 degraded 支同姿势：不隐藏（PFRO 里可能仍挂着登记）、置灰、data-tip 说明。
        revBtn.style.display = '';
        revBtn.disabled = true;
        revBtn.textContent = '重启后删状态未知';
        revBtn.setAttribute('data-tip', '待删清单读取失败（' + ((e && e.message) || e) + '），无法确认哪些条目仍挂起；PFRO 里的登记可能仍会在下次重启时执行。');
      });
    }
  }

  async function revokePendingDeletes() {
    // F4a1-M09：撤回是**安全方向**（把登记摘掉、文件保持原样），走黄档 warning；
    // 与主窗同一动作同档（cleanup.js 的 openPendingListModal）——两窗档位相反会训练用户
    // 「红色也可以直接点」，稀释真正不可逆操作的警示强度。
    // F4a1-M04：与另两处确认同姿势——撤回是本窗「重启前可撤回」的唯一前端出口，
    // 确认件异常时必须明示且不动作，不能静默成「点了没反应」。
    let ok = false;
    try {
      ok = await confirmViaModal({
        title: '撤回重启后删除',
        message: '将把已登记的「重启后删除」条目从系统中摘除：相关文件不会被删除，保持原样。',
        confirmText: '撤回全部',
        cancelText: '取消',
        warning: true
      });
    } catch (e) {
      toast('error', '确认组件异常，本次不撤回任何登记');
      return;
    }
    if (!ok) return;
    try {
      const resp = await window.api.uninstall.pendingRevoke();
      if (!resp.success) throw new Error(resp.message || '撤回失败');
      toast('success', `已撤回 ${(resp.data && resp.data.revoked) || 0} 项登记，相关文件不会被删除`);
      updatePendingButtons();
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
      else toast('warning', '这条详情已经过期，请重新扫描');
      return;
    }
    const t = e.target.closest('[data-rcheck]');
    if (t) {
      const f = state.rows[Number(t.dataset.rcheck)];
      if (!f) return;
      f._checked = !f._checked;
      t.classList.toggle('checked', f._checked);
      t.setAttribute('aria-checked', f._checked ? 'true' : 'false');
      const tr = t.closest('tr');
      if (tr) tr.classList.toggle('finder-row-selected', f._checked);
      updateActionButtons();
    }
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
    // F4a1-L03：键盘激活走 ds.bindCheckboxKeys（宿主缺失时它自己早退，缺件告警由上一行
    // 的 on('rsChainBody','click') 给出），不再本窗自写一份伪造 onClick({target}) 的处理器。
    window.ds?.bindCheckboxKeys?.(el('rsChainBody'), '[data-rcheck]');
    on('rsRescanBtn', 'click', scanAll);
    on('rsBtnClean', 'click', cleanSelected);
    on('rsBtnPendingRevoke', 'click', revokePendingDeletes);
    on('rsCloseBtn', 'click', function () {
      window.api.residueWindow.closeWindow().catch(function () { toast('warning', '关闭窗口失败，请手动关闭'); });
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
    // F4a1-M10：开窗即刷一次「撤回重启后删」入口——本窗正是卸载后被自动弹出的那扇窗，
    // 遗留的永久删登记项若不在此现，界面上就没有任何「还挂着待删项」的痕迹，等于违背
    // 「待删清单可见且重启前可撤回」这条受控例外约束。只按 pendingList 回执刷 revBtn 显隐。
    updatePendingButtons();
    scanAll();
  });
})();
