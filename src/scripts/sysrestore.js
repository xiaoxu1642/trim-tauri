// sysrestore.js - 系统还原点管理模块（弹窗版）
// 入口：电脑优化中心右上角「系统还原点」按钮，弹窗展示（样式与「大模型管理」一致）。
// 通过系统 API（Get-ComputerRestorePoint / SystemRestore WMI）查看、创建与管理还原点。
(function () {
  'use strict';

  let loading = false;
  let backdrop = null;   // 当前弹窗遮罩（v3.2.0：骨架由 modal.js 工厂创建）

  function q(sel) { return backdrop ? backdrop.querySelector(sel) : null; }

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  function fmtTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '-';
    const p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  function fmtRelative(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '-';
    const diff = Date.now() - d.getTime();
    if (diff < 0) return fmtTime(iso);
    const min = Math.floor(diff / 60000);
    if (min < 1) return '刚刚';
    if (min < 60) return `${min} 分钟前`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr} 小时前`;
    const day = Math.floor(hr / 24);
    return `${day} 天前`;
  }

  async function load() {
    if (loading || !backdrop) return;
    if (!window.api?.optimizer?.listRestore) {
      setListError('系统还原点管理仅在 Electron 环境中可用');
      return;
    }
    loading = true;
    try {
      const prot = q('#restoreProtection');
      if (prot) prot.textContent = '检测中…';
      const resp = await window.api.optimizer.listRestore();
      if (!resp || !resp.success) {
        setListError((resp && resp.message) || '读取还原点失败');
        return;
      }
      render(resp.data || {});
    } catch (e) {
      setListError(`读取还原点失败: ${e.message}`);
    } finally {
      loading = false;
    }
  }

  function render(data) {
    if (!backdrop) return;
    const rps = Array.isArray(data.restorePoints) ? data.restorePoints : [];
    const prot = Array.isArray(data.protection) ? data.protection : [];
    const globalDisabled = !!data.globalDisabled;

    const protEl = q('#restoreProtection');
    // 复核 💭2（2026-09-16）：与其它元素同口径判空，骨架未挂载时不抛错
    if (protEl) {
      if (globalDisabled) {
        protEl.textContent = '已禁用';
        protEl.className = 'summary-value text-danger';
      } else if (prot.length) {
        protEl.textContent = '已开启';
        protEl.className = 'summary-value text-success';
      } else {
        protEl.textContent = '已关闭';
        protEl.className = 'summary-value text-danger';
      }
    }
    const cnt = q('#restoreCount');
    if (cnt) cnt.textContent = rps.length;
    const recent = q('#restoreRecent');
    if (recent) recent.textContent = rps.length ? fmtRelative(rps[0].created) : '无';
    const lc = q('#restoreListCount');
    if (lc) lc.textContent = `${rps.length} 个`;

    const listEl = q('#restoreList');
    if (!listEl) return;
    if (!rps.length) {
      listEl.innerHTML = window.emptyState
        ? window.emptyState({ icon: 'shield', title: '暂无还原点', desc: '系统还原点用于系统异常时一键回退，建议优化前先创建', cta: { text: '创建还原点', target: 'btnRestoreCreate' } })
        : '<div class="empty-state"><p>暂无还原点，点击底部「创建还原点」立即创建一个</p></div>';
      return;
    }
    const protBadges = prot.map(p =>
      `<span class="restore-vol on">${escapeHtml(p.drive)} 保护开</span>`
    ).join('');

    listEl.innerHTML = rps.map((rp, i) => `
      <div class="restore-item">
        <div class="restore-item-icon">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 5V1L7 6l5 5V7c3.31 0 6 2.69 6 6s-2.69 6-6 6-6-2.69-6-6H4c0 4.42 3.58 8 8 8s8-3.58 8-8-3.58-8-8-8z"/></svg>
        </div>
        <div class="restore-item-info">
          <div class="restore-item-title">${escapeHtml(rp.desc || ('还原点 ' + (i + 1)))}</div>
          <div class="restore-item-meta">创建于 ${fmtTime(rp.created)} · ${fmtRelative(rp.created)}</div>
        </div>
        <span class="restore-item-seq">#${escapeHtml(String(rp.seq))}</span>
      </div>
    `).join('') + (protBadges ? `<div class="restore-vols">${protBadges}</div>` : '');
  }

  function setListError(msg) {
    if (!backdrop) return;
    const prot = q('#restoreProtection');
    if (prot) { prot.textContent = '未知'; prot.className = 'summary-value'; }
    const cnt = q('#restoreCount'); if (cnt) cnt.textContent = '-';
    const recent = q('#restoreRecent'); if (recent) recent.textContent = '-';
    const lc = q('#restoreListCount'); if (lc) lc.textContent = '0 个';
    const listEl = q('#restoreList');
    if (listEl) listEl.innerHTML = `<div class="empty-state"><p>${escapeHtml(msg)}</p></div>`;
  }

  async function create() {
    if (!window.api?.optimizer?.createRestore) {
      window.app?.toast('error', '创建功能仅在 Electron 环境中可用');
      return;
    }
    // 复核 💭3（2026-09-16）：confirmDanger 链路判空，预览模式（无 app.js 提供方）不抛错
    const ok = await window.app?.confirmDanger?.(
      '创建系统还原点',
      '系统还原点用于系统异常时一键回退。\n\n即将为所有已启用保护的磁盘创建还原点。',
      '创建',
      '取消',
      '此操作为系统级操作，创建过程可能需要数十秒，请确认当前无其他系统任务正在进行。'
    );
    if (!ok) return;
    const btn = q('#btnRestoreCreate');
    if (!btn) return;
    const oldText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '创建中…';
    try {
      const resp = await window.api.optimizer.createRestore();
      // 复核 💭7（提权半闭环，2026-09-16）：服务端已补 needAdmin 门禁回传，
      // 此处弹提权确认（原先只 toast 笼统错误，无提权入口）
      if (resp && resp.needAdmin) {
        const elevated = await window.app?.requestElevation?.('创建系统还原点需要管理员权限。');
        if (elevated) window.app?.toast('info', '已获得管理员权限，请重新点击「创建还原点」');
        return;
      }
      if (resp && resp.success) {
        window.app?.toast('success', '系统还原点创建成功');
        await load();
      } else {
        window.app?.toast('warning', (resp && resp.message) || '创建失败，建议手动创建');
      }
    } catch (e) {
      window.app?.toast('error', `创建失败: ${e.message}`);
    } finally {
      btn.disabled = false;
      btn.innerHTML = oldText;
    }
  }

  function open() {
    close();
    // v3.2.0 弹窗统一批次：骨架改由 modal.js 工厂生成（body 内部结构与 id 引用 q() 不变）
    const bodyHtml = `
          <div class="summary-cards rt-sr-cards">
            <div class="summary-card">
              <div class="summary-icon" style="--icon-bg: var(--info-soft); color: var(--info)"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5l8 3.5v5.2c0 4.9-3.4 9.4-8 10.8-4.6-1.4-8-5.9-8-10.8V6l8-3.5z"/><path d="M8.5 12l2.4 2.4 4.6-5"/></svg></div>
              <div class="summary-info">
                <div class="summary-value" id="restoreProtection">检测中…</div>
                <div class="summary-label">系统保护状态</div>
              </div>
            </div>
            <div class="summary-card">
              <div class="summary-icon" style="--icon-bg: var(--success-soft); color: var(--success)"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg></div>
              <div class="summary-info">
                <div class="summary-value" id="restoreCount">-</div>
                <div class="summary-label">还原点数量</div>
              </div>
            </div>
            <div class="summary-card">
              <div class="summary-icon" style="--icon-bg: var(--warning-soft); color: var(--warning)"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 12a8.5 8.5 0 1 0 2.8-6.3L3.5 8"/><path d="M3.5 3.5V8H8"/></svg></div>
              <div class="summary-info">
                <div class="summary-value" id="restoreRecent">-</div>
                <div class="summary-label">最近还原点</div>
              </div>
            </div>
          </div>
          <div class="rt-sr-panel">
            <div class="rt-sr-panel-head">
              <h3>还原点列表</h3>
              <span class="opt-group-count" id="restoreListCount">0 个</span>
            </div>
            <div class="restore-list" id="restoreList">
              <div class="empty-state"><p>暂无还原点</p></div>
            </div>
          </div>`;
    const footerHtml = `
          <span class="pw-last-scan">系统还原点用于系统异常时一键回退，建议优化前先创建</span>
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary" id="btnRestoreRefresh" type="button">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor"><path d="M17.65 6.35A7.958 7.958 0 0 0 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0 1 12 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>
            刷新
          </button>
          <button class="btn btn-accent" id="btnRestoreCreate" type="button">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
            创建还原点
          </button>
          <button class="btn btn-primary" id="btnSrClose" type="button">完成</button>`;
    const ctrl = window.modal.create({
      id: 'sysRestoreBackdrop',
      title: '系统还原点管理',
      backdropClass: 'rt-sr-backdrop',
      modalClass: 'rt-sr-modal',
      bodyClass: 'rt-sr-body',
      bodyHtml,
      footerHtml,
      onClose() { backdrop = null; }
    });
    backdrop = ctrl.backdrop;

    ctrl.footer.querySelector('#btnSrClose').addEventListener('click', close);
    ctrl.footer.querySelector('#btnRestoreRefresh').addEventListener('click', () => load());
    ctrl.footer.querySelector('#btnRestoreCreate').addEventListener('click', () => create());

    load();
  }

  function close() {
    // v3.2.0：骨架由 modal.js 工厂创建，close 即销毁（Esc/遮罩由工厂接管）
    if (backdrop) { const el = backdrop; backdrop = null; el.remove(); }
  }

  function init() {
    document.getElementById('btnSysRestore')?.addEventListener('click', open);
  }

  window.sysrestore = { init, open, close, load };
})();
