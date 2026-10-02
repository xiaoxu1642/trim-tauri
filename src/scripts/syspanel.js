// syspanel.js — 电源计划读写 + 虚拟内存只读面板（P2 §3.6 RAINZ 对标）
// 挂在 settings 页底部；由 app.js 的 PAGE_SCRIPTS.settings 按需注入、MODULES_NEEDING_INIT 显式调 init。
// 三条通道都走 window.api.syspanel.*（对应 CHANNEL_MAP 三个键）；后端一律 `guard(MAIN)`。
// 转义与字节格式化一律走 window.ds（AGENTS §2 硬红线，本地 escape 不许新增）。
(function () {
  'use strict';

  let inited = false;
  let powerLoaded = false;

  function esc(t) { return window.ds.esc(t); }
  function escAttr(t) { return window.ds.escAttr(t); }

  function mountPower() { return document.getElementById('syspanelPowerBody'); }
  function mountPagefile() { return document.getElementById('syspanelPagefileBody'); }

  function renderPowerEmpty(msg) {
    const el = mountPower();
    if (el) el.innerHTML = `<p class="empty-state"><span>${esc(msg)}</span></p>`;
  }

  function renderPower(state) {
    const el = mountPower();
    if (!el) return;
    const active = String(state.activeGuid || '').toLowerCase();
    const activeName = String(state.activeName || '');
    const opts = Array.isArray(state.options) ? state.options : [];
    // 白名单三档优先展示（顺序固定：平衡 / 节能 / 高性能），自定义方案跟在后面并显式禁用
    const KNOWN = [
      ['381b4222-f694-41f0-9685-ff5bb260df2e', '平衡', '系统默认；日常与办公最稳'],
      ['a1841308-3541-4fab-bc81-f71556f20b4a', '节能', '笔记本续航优先；性能受限'],
      ['8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c', '高性能', '台式机与游戏优先；功耗上升'],
    ];
    const extra = opts.filter((o) => !o.known);
    const rows = KNOWN.map(([guid, label, tip]) => {
      const isActive = active === guid;
      const checked = isActive ? ' checked' : '';
      const disabled = isActive ? ' disabled' : '';
      return `
        <label class="syspanel-radio" data-active="${isActive ? '1' : ''}">
          <input type="radio" name="syspanelPower" value="${escAttr(guid)}"${checked}${disabled}>
          <span class="syspanel-radio-main">
            <span class="syspanel-radio-label">${esc(label)}${isActive ? ' <span class="syspanel-badge">当前</span>' : ''}</span>
            <span class="syspanel-radio-tip" data-tip="${escAttr(tip)}">${esc(tip)}</span>
          </span>
        </label>`;
    }).join('');
    const extrasHtml = extra.length
      ? `<p class="syspanel-note">另有 ${extra.length} 个自定义方案（Trim 白名单外，仅展示不可选）：${extra.map((o) => esc(o.name || o.guid)).join('、')}</p>`
      : '';
    el.innerHTML = `
      <div class="syspanel-power-current">当前方案：<strong>${esc(activeName || '未知')}</strong></div>
      <div class="syspanel-radios">${rows}</div>
      <div class="syspanel-actions">
        <button type="button" class="btn btn-primary btn-small" id="btnSyspanelPowerApply">应用所选方案</button>
      </div>
      ${extrasHtml}
    `;
    document.getElementById('btnSyspanelPowerApply')?.addEventListener('click', onApplyPower);
  }

  function renderPagefile(state) {
    const el = mountPagefile();
    if (!el) return;
    const managed = !!state.managed;
    const entries = Array.isArray(state.entries) ? state.entries : [];
    const modeText = managed ? '系统托管（自动管理分页文件大小）' : '手动配置';
    const rows = entries.length
      ? entries.map((e) => {
          const initMb = Number(e.initialMb) || 0;
          const maxMb = Number(e.maxMb) || 0;
          const fmt = (n) => (n === 0 ? '0 MB' : (n >= 1024 ? window.ds.fmtBytes(n * 1024 * 1024) : n + ' MB'));
          return `<tr><td>${esc(e.path || '(未设置)')}</td><td>${esc(fmt(initMb))}</td><td>${esc(fmt(maxMb))}</td></tr>`;
        }).join('')
      : '<tr><td colspan="3" class="empty-cell">未读到 PagingFiles 项（可能全在托管模式）</td></tr>';
    el.innerHTML = `
      <p class="syspanel-pf-mode">${esc(modeText)}</p>
      <table class="syspanel-pf-table">
        <thead><tr><th>路径</th><th>初始大小</th><th>最大值</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p class="syspanel-pf-hint">改虚拟内存**需要重启才生效**；配错（例如把全部卷都关完）可能让物理内存耗尽时蓝屏。写前 Trim 会把当前配置备份到应用私有备份目录，可通过导入备份手动回退。</p>
      <div class="syspanel-pf-actions">
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPfEdit">编辑配置</button>
      </div>
      <div id="syspanelPfEditor" style="display:none"></div>
    `;
    document.getElementById('btnSyspanelPfEdit')?.addEventListener('click', () => enterPfEditor(state));
  }

  /** 进入编辑态：把当前 state 摊成表单。用户可以直接改 managed 复选框、增删卷、改 MB 数。 */
  function enterPfEditor(state) {
    const mount = document.getElementById('syspanelPfEditor');
    const btn = document.getElementById('btnSyspanelPfEdit');
    if (!mount) return;
    if (btn) btn.style.display = 'none';
    mount.style.display = '';
    const managed = !!state.managed;
    const entries = (Array.isArray(state.entries) ? state.entries : []).map((e) => {
      // 从 "C:\pagefile.sys 8192 16384" 反推 drive/initial/max；失败退到 C:
      const m = String(e.path || '').match(/^([A-Za-z]:)/);
      return {
        drive: m ? m[1].toUpperCase() : 'C:',
        initialMb: Number(e.initialMb) || 0,
        maxMb: Number(e.maxMb) || 0,
      };
    });
    const renderRows = (list) => list.map((e, i) => `
      <tr>
        <td><input type="text" class="syspanel-pf-input syspanel-pf-drive" data-idx="${i}" value="${escAttr(e.drive)}" maxlength="2" data-tip="盘符，如 C: 或 D:" /></td>
        <td><input type="number" class="syspanel-pf-input" data-idx="${i}" data-field="initialMb" value="${e.initialMb}" min="0" max="1048576" step="1" /></td>
        <td><input type="number" class="syspanel-pf-input" data-idx="${i}" data-field="maxMb" value="${e.maxMb}" min="0" max="1048576" step="1" /></td>
        <td><button type="button" class="btn btn-secondary btn-small" data-pf-remove="${i}">删除</button></td>
      </tr>`).join('');
    mount.innerHTML = `
      <label class="syspanel-pf-managed">
        <input type="checkbox" id="syspanelPfManaged" ${managed ? 'checked' : ''} />
        <span>由系统自动管理分页文件大小（推荐；勾选则下方配置不生效）</span>
      </label>
      <div id="syspanelPfManualArea" class="syspanel-pf-manual-area">
        <table class="syspanel-pf-table">
          <thead><tr><th>盘符</th><th>初始 (MB)</th><th>最大 (MB)</th><th></th></tr></thead>
          <tbody id="syspanelPfTbody">${renderRows(entries)}</tbody>
        </table>
        <div class="syspanel-pf-tools">
          <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPfAdd">+ 添加卷</button>
        </div>
      </div>
      <div class="syspanel-pf-actions">
        <button type="button" class="btn btn-primary btn-small" id="btnSyspanelPfApply">应用配置</button>
        <button type="button" class="btn btn-secondary btn-small" id="btnSyspanelPfCancel">取消</button>
      </div>
    `;
    const managedBox = document.getElementById('syspanelPfManaged');
    const manualArea = document.getElementById('syspanelPfManualArea');
    const syncManualArea = () => { if (manualArea) manualArea.style.display = managedBox?.checked ? 'none' : ''; };
    managedBox?.addEventListener('change', syncManualArea);
    syncManualArea();
    document.getElementById('btnSyspanelPfAdd')?.addEventListener('click', () => {
      const list = collectPfForm();
      list.push({ drive: 'D:', initialMb: 0, maxMb: 4096 });
      document.getElementById('syspanelPfTbody').innerHTML = renderRows(list);
    });
    mount.querySelectorAll('[data-pf-remove]').forEach((b) => b.addEventListener('click', () => {
      const idx = Number(b.dataset.pfRemove);
      const list = collectPfForm();
      list.splice(idx, 1);
      document.getElementById('syspanelPfTbody').innerHTML = renderRows(list);
    }));
    document.getElementById('btnSyspanelPfCancel')?.addEventListener('click', () => {
      mount.style.display = 'none';
      if (btn) btn.style.display = '';
    });
    document.getElementById('btnSyspanelPfApply')?.addEventListener('click', () => applyPagefile(managedBox?.checked, collectPfForm()));
  }

  function collectPfForm() {
    const rows = document.querySelectorAll('#syspanelPfTbody tr');
    const list = [];
    rows.forEach((tr) => {
      const driveEl = tr.querySelector('.syspanel-pf-drive');
      const initEl = tr.querySelector('[data-field="initialMb"]');
      const maxEl = tr.querySelector('[data-field="maxMb"]');
      if (!driveEl || !initEl || !maxEl) return;
      list.push({
        drive: driveEl.value.trim(),
        initialMb: Number(initEl.value) || 0,
        maxMb: Number(maxEl.value) || 0,
      });
    });
    return list;
  }

  async function applyPagefile(managed, entries) {
    if (!window.api?.syspanel?.pagefileApply) {
      window.app?.toast?.('warning', '当前环境不支持写虚拟内存');
      return;
    }
    // 高危二次确认：AGENTS §3 危险能力显式确认。文案里明说蓝屏风险与重启需求，
    // 免得用户只看到"应用"按钮就点下去。位置参数形态（AGENTS §5 confirm 禁对象）。
    const ok = await window.app?.confirmDanger?.(
      '修改虚拟内存配置',
      `即将把虚拟内存改为「${managed ? '系统托管' : '手动配置（' + entries.length + ' 个卷）'}」。\n`
        + '\n必须知道：\n'
        + '· 需要**重启**才生效；\n'
        + '· 全部关完会让物理内存耗尽时直接蓝屏，Trim 参数校验层会拒这种配置；\n'
        + '· 改前当前配置已备份，可通过导入备份 JSON 手动回退。',
      '我已了解，应用',
      '取消',
      '此操作会修改 HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management。'
    );
    if (!ok) return;
    const btn = document.getElementById('btnSyspanelPfApply');
    if (btn) { btn.disabled = true; btn.textContent = '写入中…'; }
    try {
      const resp = await window.api.syspanel.pagefileApply(!!managed, entries);
      if (resp && resp.success) {
        const data = resp.data || {};
        window.app?.toast?.('info', '虚拟内存配置已写入并回读校验通过；**需要重启生效**');
        // 重渲染只读视图（走 loadPagefile）
        await loadPagefile();
        if (data.backupPath) {
          const el = mountPagefile();
          if (el) {
            const hint = document.createElement('p');
            hint.className = 'syspanel-pf-hint syspanel-pf-backup';
            hint.textContent = '本次改前配置已备份到：' + data.backupPath;
            el.appendChild(hint);
          }
        }
      } else {
        window.app?.toast?.('error', (resp && resp.message) || '写入失败');
      }
    } catch (e) {
      window.app?.toast?.('error', '写入异常：' + (e && e.message ? e.message : String(e)));
    } finally {
      const b2 = document.getElementById('btnSyspanelPfApply');
      if (b2) { b2.disabled = false; b2.textContent = '应用配置'; }
    }
  }

  async function loadPower() {
    if (!window.api?.syspanel?.powerPlanGet) {
      renderPowerEmpty('当前环境不支持读取电源方案');
      return;
    }
    try {
      const resp = await window.api.syspanel.powerPlanGet();
      const data = resp && resp.success ? resp.data : null;
      if (!data) { renderPowerEmpty((resp && resp.message) || '读取电源方案失败'); return; }
      renderPower(data);
      powerLoaded = true;
    } catch (e) {
      renderPowerEmpty('读取失败：' + (e && e.message ? e.message : String(e)));
    }
  }

  async function loadPagefile() {
    if (!mountPagefile()) return;
    if (!window.api?.syspanel?.pagefileState) {
      mountPagefile().innerHTML = '<p class="empty-state"><span>当前环境不支持读取虚拟内存</span></p>';
      return;
    }
    try {
      const resp = await window.api.syspanel.pagefileState();
      const data = resp && resp.success ? resp.data : null;
      if (!data) {
        mountPagefile().innerHTML = `<p class="empty-state"><span>${esc((resp && resp.message) || '读取虚拟内存失败')}</span></p>`;
        return;
      }
      renderPagefile(data);
    } catch (e) {
      mountPagefile().innerHTML = `<p class="empty-state"><span>读取失败：${esc(e && e.message ? e.message : String(e))}</span></p>`;
    }
  }

  async function onApplyPower() {
    const chosen = document.querySelector('input[name="syspanelPower"]:checked');
    if (!chosen) {
      window.app?.toast?.('warning', '请先选择一档电源方案');
      return;
    }
    const guid = chosen.value;
    const label = chosen.closest('.syspanel-radio')?.querySelector('.syspanel-radio-label')?.firstChild?.nodeValue?.trim() || guid;
    // 电源方案切换会立即影响功耗与温度：走 confirmWarning，不走 confirmDanger（可回切、非破坏性）
    const ok = await window.app?.confirmWarning?.(
      '切换电源方案',
      `确认切换到「${label}」？切换后系统会立刻按新方案调度 CPU 与外设电源。`,
      '应用',
      '取消',
      'Trim 只允许在平衡 / 节能 / 高性能 三档 GUID 之间切换；改完会 400 ms 后回读校验。'
    );
    if (!ok) return;
    const btn = document.getElementById('btnSyspanelPowerApply');
    if (btn) { btn.disabled = true; btn.textContent = '切换中…'; }
    try {
      const resp = await window.api.syspanel.powerPlanApply(guid);
      if (resp && resp.success) {
        renderPower(resp.data);
        window.app?.toast?.('info', '电源方案已切换并回读校验通过');
      } else {
        window.app?.toast?.('error', (resp && resp.message) || '切换失败');
        await loadPower(); // 失败后**重读**，把实际状态摆回面板（不假装成功）
      }
    } catch (e) {
      window.app?.toast?.('error', '切换异常：' + (e && e.message ? e.message : String(e)));
      await loadPower();
    } finally {
      const b2 = document.getElementById('btnSyspanelPowerApply');
      if (b2) { b2.disabled = false; b2.textContent = '应用所选方案'; }
    }
  }

  function init() {
    if (inited) return;
    inited = true;
    document.getElementById('btnSyspanelPowerRefresh')?.addEventListener('click', () => loadPower());
    // 首帧进 settings 页时拉一次；后续靠"刷新"按钮再拉。
    if (!powerLoaded) {
      loadPower();
    }
    loadPagefile();
  }

  window.syspanel = { init, loadPower, loadPagefile };

  // 延迟加载脚本守卫（AGENTS §4 check-idle-scripts 断言 1）：顶层 DOMContentLoaded 注册
  // 必须在 readyState 判定内；本文件是"按需注入"，注入时通常已 Completed，走 else 立即 init。
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => init());
  } else {
    init();
  }
})();
