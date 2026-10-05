// actions-window.js - 「右键菜单动作」副窗（v0.7.0 第四期）。
//
// 这一窗只做一件事：把随包清单里的动作投影成 HKCU 经典菜单键。三条来自裁定的边界：
//   ① 只写当前账号（HKCU），代码里根本没有 HKLM 支路；
//   ② 界面只回传 id，命令串由后端从 `data/contextmenu-items.json` 取（§9.1 不透传外部命令）；
//   ③ 写与删都是改系统状态 ⇒ 逐项确认，确认件不在就拒执行（fail-closed）。
// 独立窗口没加载 app.js：toast 走 sub-toast，确认走 window.modal.confirm。
(function () {
  'use strict';

  function el(id) { return document.getElementById(id); }
  function esc(s) { return window.ds.esc(String(s == null ? '' : s)); }
  function toast(type, msg) { window.subToast?.hintLine('acGlobalHint', type, msg); }

  const state = { items: [], checked: new Set(), dropped: 0, busy: false };

  async function confirmChange(opts) {
    // 确认组件没加载成功 ⇒ 拒绝执行：跳过确认直接改注册表是不可接受的
    if (!window.modal || typeof window.modal.confirm !== 'function') {
      toast('error', '确认组件未加载，本次不写入也不删除任何菜单项');
      return false;
    }
    return await window.modal.confirm(opts);
  }

  async function load() {
    el('acSummary').textContent = '正在读取…';
    try {
      const r = await window.api.actionsWindow.list();
      if (!r || r.success !== true) throw new Error((r && (r.message || (r.error && r.error.message))) || '读取失败');
      state.items = (r.data && r.data.items) || [];
      state.dropped = (r.data && r.data.droppedInvalid) || 0;
      render();
    } catch (e) {
      el('acBody').innerHTML = '<div class="finder-empty">读取失败：' + esc((e && e.message) || e) + '</div>';
      toast('error', '读取内置动作失败：' + ((e && e.message) || e));
    }
  }

  function render() {
    if (!state.items.length) {
      el('acSummary').textContent = '清单为空';
      el('acBody').innerHTML = '<div class="finder-empty">随包清单里没有任何可用动作。</div>';
      updateButtons();
      return;
    }
    const installed = state.items.filter(function (i) { return i.installed; }).length;
    el('acSummary').textContent = '共 ' + state.items.length + ' 项，已写入 ' + installed + ' 项'
      + (state.dropped ? ' · 另有 ' + state.dropped + ' 项未通过校验被跳过（不会静默消失）' : '');
    const rows = state.items.map(function (it, i) {
      const on = state.checked.has(it.id);
      return '<tr class="' + (on ? 'finder-row-selected' : '') + '">'
        + '<td style="width:34px"><span class="checkbox' + (on ? ' checked' : '') + '" data-acheck="' + i
        + '" tabindex="0" role="checkbox" aria-checked="' + (on ? 'true' : 'false') + '"></span></td>'
        + '<td><div class="finder-cell"><span class="finder-path-text">' + esc(it.title) + '</span></div></td>'
        + '<td style="width:120px">' + (it.installed
          ? '<span class="badge badge-ok">已写入</span>'
          : '<span class="badge">未写入</span>') + '</td>'
        + '</tr>';
    }).join('');
    el('acBody').innerHTML = '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>动作</th><th style="width:120px">状态</th></tr></thead><tbody>' + rows + '</tbody></table>';
    updateButtons();
  }

  function updateButtons() {
    const any = state.checked.size > 0;
    el('acApplyBtn').disabled = !any || state.busy;
    const sb = el('acRunBtn');
    if (sb) sb.disabled = state.busy || !(el('acScript').value || '').trim();
    el('acRemoveBtn').disabled = !any || state.busy;
  }

  function idsOfSelected(installedOnly) {
    return state.items
      .filter(function (it) { return state.checked.has(it.id) && (!installedOnly || it.installed); })
      .map(function (it) { return it.id; });
  }

  async function apply() {
    const ids = idsOfSelected(false);
    if (!ids.length || state.busy) return;
    const ok = await confirmChange({
      title: '写入右键菜单项',
      message: '将在当前账号的 HKCU\\Software\\Classes 下写入 ' + ids.length + ' 个自定义菜单项（只影响你自己这个 Windows 账号，不需要管理员）。',
      confirmText: '写入',
      cancelText: '取消',
      danger: true,
      dangerHint: '已开着的资源管理器窗口可能不会立刻刷新，没出现就重启一次资源管理器。'
    });
    if (!ok) return;
    await run('apply', ids);
  }

  async function remove() {
    const ids = idsOfSelected(true);
    if (!ids.length || state.busy) return;
    const ok = await confirmChange({
      title: '移除右键菜单项',
      message: '将删除这些动作写过的 HKCU 键（' + ids.length + ' 项）。清单之外的键一项都不碰 —— 别的软件的菜单项不会受影响。',
      confirmText: '移除',
      cancelText: '取消',
      danger: true
    });
    if (!ok) return;
    await run('remove', ids);
  }

  async function run(op, ids) {
    state.busy = true;
    updateButtons();
    try {
      const fn = op === 'apply' ? window.api.actionsWindow.apply : window.api.actionsWindow.remove;
      const r = await fn(ids);
      if (!r || r.success !== true) throw new Error((r && r.message) || '操作失败');
      const d = r.data || {};
      const failed = (d.details || []).filter(function (x) { return x.status !== 'ok'; });
      if (failed.length) {
        toast('warning', (op === 'apply' ? '写入' : '移除') + '完成 ' + (d.okCount || 0) + ' 项，' + failed.length + ' 项未执行：' + failed[0].message);
      } else {
        toast('success', (op === 'apply' ? '已写入 ' : '已移除 ') + (d.okCount || 0) + ' 项'
          + (op === 'apply' ? '；没在资源管理器里看到新条目？重启一次资源管理器即可' : ''));
      }
      state.checked.clear();
      await load();
    } catch (e) {
      toast('error', '操作失败：' + ((e && e.message) || e));
    } finally {
      state.busy = false;
      updateButtons();
    }
  }

  function onClick(e) {
    const t = e.target.closest('[data-acheck]');
    if (!t) return;
    const it = state.items[Number(t.dataset.acheck)];
    if (!it) return;
    if (state.checked.has(it.id)) state.checked.delete(it.id); else state.checked.add(it.id);
    render();
  }

  function onKeydown(e) {
    if (e.key !== ' ' && e.key !== 'Enter') return;
    const t = e.target.closest && e.target.closest('[data-acheck]');
    if (!t) return;
    e.preventDefault();
    onClick({ target: t });
  }

  async function runScript() {
    const src = (el('acScript').value || '').trim();
    if (!src || state.busy) return;
    const ok = await confirmChange({
      title: '运行自己写的 PowerShell 脚本',
      message: '将在当前账号的 PowerShell 里执行这段脚本（通常非提权，固定 120 秒超时）。',
      confirmText: '运行',
      cancelText: '取消',
      danger: true,
      dangerHint: '脚本不经过 Trim 的删除红线：A1 禁删面与回收站优先都不在它路上。Remove-Item 这类语句会以你当前权限直接生效，请自己确认过内容。'
    });
    if (!ok) return;
    state.busy = true;
    updateButtons();
    try {
      const r = await window.api.actionsWindow.runScript(src);
      if (!r || r.success !== true) throw new Error((r && r.message) || '执行失败');
      const d = r.data || {};
      const out = el('acOutput');
      out.hidden = false;
      out.textContent = 'exit=' + (d.exitCode == null ? '?' : d.exitCode)
        + (d.timedOut ? ' · 超时被终止（子进程一并收掉）' : '')
        + (d.elevated ? ' · 当前是高权限令牌' : '')
        + '\n\n' + String(d.stdout || '') + (d.stderr ? '\n[stderr]\n' + d.stderr : '');
      toast(d.exitCode === 0 ? 'success' : 'warning', d.exitCode === 0 ? '脚本执行完成' : '脚本返回非零退出码 ' + d.exitCode);
    } catch (e) {
      toast('error', '脚本执行失败：' + ((e && e.message) || e));
    } finally {
      state.busy = false;
      updateButtons();
    }
  }

  // 与残留副窗同一条纪律（见 residue-window.js 里 on() 的注释）：绑定按 id 走这个口子，
  // 缺件只降级成控制台告警。副窗的初始化一旦抛错就再也不会发起首次加载，
  // 而真机症状长得像"功能没做"，Node 门禁与 cargo 测试都碰不到 DOM。
  function on(id, type, handler) {
    const node = el(id);
    if (!node) {
      console.warn('[actions-window] 缺少元素 #' + id + '，' + type + ' 未绑定');
      return false;
    }
    node.addEventListener(type, handler);
    return true;
  }

  document.addEventListener('DOMContentLoaded', function () {
    on('acBody', 'click', onClick);
    on('acBody', 'keydown', onKeydown);
    on('acRefreshBtn', 'click', load);
    on('acRunBtn', 'click', runScript);
    on('acScript', 'input', updateButtons);
    on('acApplyBtn', 'click', apply);
    on('acRemoveBtn', 'click', remove);
    on('acCloseBtn', 'click', function () {
      window.api.actionsWindow.closeWindow().catch(function () { toast('warn', '关闭失败，请手动关闭'); });
    });
    load().catch(function (e) {
      toast('error', '清单加载失败：' + ((e && e.message) || e));
    });
  });
})();
