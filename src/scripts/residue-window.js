// residue-window.js - 「应用卸载残留扫描」副窗口（v0.5.0 只读报告）。
//
// 方案 §1 裁决 4：残留扫描全部在这个自绘副窗里完成，主窗只留入口。
// v0.5.0 只有报告：整页没有任何勾选框、没有删除按钮 —— 前端的「不可删」不是靠隐藏按钮
// 装饰出来的，后端同轮已经保证了三件事：命令只读、不写执行快照、目标一律 defaultChecked:false。
// 因此这里刻意不去读 defaultChecked 渲染勾选，而是把它当断言用：一旦发现某条带着
// defaultChecked:true 回来，就显式标出来（说明后端形态与本页契约漂移了）。
//
// 注意：独立窗口未加载 app.js —— toast 走 scripts/sub-toast.js（window.app 在本窗不存在）。
(function () {
  'use strict';

  function el(id) { return document.getElementById(id); }
  function esc(s) { return window.ds.esc(String(s == null ? '' : s)); }

  function toast(type, message) { window.subToast?.hintLine('rsGlobalHint', type, message); }

  // 分组渲染顺序由后端 groups 决定，前端不再排 —— 两处各排一遍迟早会不一致
  var state = { report: null, filter: '' };

  function passes(item) {
    var q = state.filter.trim().toLowerCase();
    if (!q) return true;
    var hay = [item.target, item.class, item.reason, item.details && item.details.serviceName, item.details && item.details.image]
      .filter(function (v) { return typeof v === 'string' && v; })
      .join('\n')
      .toLowerCase();
    return hay.indexOf(q) >= 0;
  }

  // 判定依据逐条摊开（contribs 的 code 是稳定标识，文案会变，按 code 寻址不按文案寻址）
  function contribLines(item) {
    var list = Array.isArray(item.contribs) ? item.contribs : [];
    if (!list.length) return '';
    return '<div class="xtable-cell-desc">' + list.map(function (c) {
      return '· ' + esc(c.text) + ' <span class="xtable-cell-muted">(' + esc(c.code) + ')</span>';
    }).join('<br>') + '</div>';
  }

  function detailsInline(item) {
    var d = item.details || {};
    var bits = [];
    if (d.serviceName) bits.push('服务名 ' + esc(d.serviceName));
    if (d.start) bits.push('启动 ' + esc(d.start));
    if (d.type) bits.push('类型 ' + esc(d.type));
    if (d.state) bits.push('状态 ' + esc(d.state));
    if (d.signer) bits.push('签名 ' + esc(d.signer));
    if (d.antiCheat) bits.push('反作弊 ' + esc(d.antiCheat));
    if (d.inLibraryGame) bits.push('在库游戏 ' + esc(d.inLibraryGame));
    if (d.image) bits.push('镜像 ' + esc(d.image));
    if (d.filterName) bits.push('滤镜 ' + esc(d.filterName) + '（高度 ' + esc(d.altitude) + '）');
    if (d.landingExists === false) bits.push('落点已失踪');
    return bits.length ? '<div class="xtable-cell-muted">' + bits.join(' · ') + '</div>' : '';
  }

  function tableHtml(title, items) {
    var head = '<div class="finder-group-header" style="margin-top:14px"><span>' + esc(title) + ' · ' + items.length + ' 项</span></div>';
    if (!items.length) return head + '<div class="finder-empty">' + esc('本组没有候选。') + '</div>';
    var rows = items.map(function (it) {
      // 只读阶段的断言：后端不该给出任何「默认选中」的候选（方案 §6：不给删除按钮）
      var drift = it.defaultChecked === true ? '<span class="badge badge-warn">形态漂移：本阶段不应有默认勾选项</span>' : '';
      return '<tr>' +
        '<td><div class="xtable-cell-path" title="' + esc(it.target) + '">' + esc(it.target) + '</div>' + detailsInline(it) + contribLines(it) + '</td>' +
        '<td style="width:110px">' + esc(it.confidence || '') + ' / ' + esc(it.risk || '') + drift + '</td>' +
        '<td style="width:200px">' + esc(it.reason || '') + '</td>' +
        '</tr>';
    }).join('');
    return head + '<table class="finder-table"><thead><tr><th>目标</th><th style="width:110px">置信 / 风险</th><th style="width:200px">判定原因</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  function summaryHtml(r) {
    var s = r.scanned || {};
    var total = (r.groups || []).reduce(function (n, g) { return n + (g.count || 0); }, 0);
    var platform = r.platforms || {};
    var parts = [
      '候选合计 ' + total + ' 项',
      '已保护 ' + (r.protectedCount || 0) + ' 项（在库 / 在用 / 微软签名）',
      '服务 ' + (s.services || 0),
      '驱动文件 ' + (s.driverFiles || 0),
      '挂载滤镜 ' + (s.mountedFilters || 0),
      'IFEO ' + (s.ifeoKeys || 0),
      '厂商产品键 ' + (s.vendorProductKeys || 0),
      '平台记录 ' + (s.platformRecords || 0)
    ];
    var html = '<div class="xtable-cell-text">' + parts.map(esc).join(' · ') + '</div>';
    if (platform.unreadable && platform.unreadable.length) {
      html += '<div class="xtable-cell-hint">平台清单未读全：' + esc(platform.unreadable.join('、'))
        + ' —— 这些平台的「游戏已卸载」判定本轮不成立，反作弊候选已按证据不足降级为不报。</div>';
    }
    var notes = Array.isArray(r.notes) ? r.notes : [];
    if (notes.length) {
      html += '<div class="xtable-cell-desc">' + notes.map(function (n) { return '· ' + esc(n); }).join('<br>') + '</div>';
    }
    return html;
  }

  function render() {
    var body = el('rsBody');
    var r = state.report;
    if (!r) { body.innerHTML = '<div class="empty-state"><p>尚无扫描结果。</p></div>'; return; }
    if (r.fatal) {
      el('rsSummary').textContent = '扫描失败';
      body.innerHTML = '<div class="empty-state"><p>' + esc(r.fatal) + '</p></div>';
      return;
    }
    el('rsSummary').innerHTML = summaryHtml(r);
    var groups = (r.groups || []).map(function (g) {
      var items = (g.items || []).filter(passes);
      return tableHtml(g.title + '（' + g.id + '）', items);
    }).join('');
    var protectedItems = (r.protected || []).filter(passes);
    var protHtml = protectedItems.length
      ? tableHtml('已保护项（只读说明，不提供操作）', protectedItems)
      : '';
    body.innerHTML = groups + protHtml;
    el('rsFootHint').textContent = '只读报告 · 本窗口不会修改本机任何文件、服务或注册表项。';
  }

  async function scan() {
    var btn = el('rsRescanBtn');
    btn.disabled = true;
    el('rsSummary').textContent = '正在扫描…';
    el('rsBody').innerHTML = '<div class="empty-state"><p>正在读取服务表、驱动目录与注册表残留…</p></div>';
    try {
      var res = await window.api.uninstall.residueDeepScan();
      if (!res || res.success !== true) {
        throw new Error((res && res.message) || '扫描命令返回失败');
      }
      state.report = res.data && res.data.report ? res.data.report : null;
      if (!state.report) throw new Error('回执里没有报告数据');
      render();
      toast('info', '扫描完成（只读，未改动本机任何东西）');
    } catch (e) {
      el('rsBody').innerHTML = '<div class="empty-state"><p>扫描失败：' + esc(e && e.message ? e.message : e) + '</p></div>';
      toast('error', '扫描失败：' + (e && e.message ? e.message : e));
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    el('rsRescanBtn').addEventListener('click', scan);
    el('rsCloseBtn').addEventListener('click', function () {
      window.api.residueWindow.closeWindow().catch(function () { toast('warn', '关闭窗口失败，请手动关闭'); });
    });
    el('rsSearch').addEventListener('input', function (e) {
      state.filter = e.target.value || '';
      render();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') window.api.residueWindow.closeWindow().catch(function () {});
    });
    scan();
  });
})();
