// uninstall.js — 软件卸载（卸载域 MVP，竞品借鉴落地方案 P0，2026-09-28）
//
// 流程（方案 §4.3，2026-09-28 二轮拍板改静默优先）：列表（uninstall:list）→ 用户点卸载
// → 红色确认 → 后端静默优先链（白名单 msi/inno/nsis 先静默；不可静默或静默失败
// 自动回退原厂 UI，返回 usedSilent/fellBack 供前端如实提示）→ 卸载后复查
// 卸载键 → 残留扫描（uninstall:residue-scan，树形分组/置信度/默认勾选）→
// 受控清理（uninstall:residue-execute：文件回收站优先、注册表先备份后删）。
// 删除确认一律走 window.app.confirmDanger（位置参数，见 memoryclean 既有用法）。
(function () {
  'use strict';

  let inited = false;
  // 当前列表缓存：id -> 记录（卸载/残留扫描按 id 寻址）
  let apps = [];
  let currentScope = 'user';
  // 两个独立互斥标志（U-8 根因修复 2026-09-28：原先共用一个 running，卸载流程内
  // 调 loadApps() 被「running 即返回」的守卫静默吞掉——列表不刷新、残留面板停在
  // 长列表首屏之下，感知就是"卸载后没有残留扫描"）。
  let running = false;      // 卸载 / 残留清理互斥
  let enumerating = false;  // 列表枚举互斥
  // 最近一次残留扫描结果（渲染与勾选用）
  let findings = [];
  let currentAppId = '';
  // 三条链（规则库 / 失效登记 / 卸载记录）共用一个面板与一份快照，分组结果留在这里渲染
  let scanGroups = [];
  // 无选中程序时的合成 id：残留不属于任何单个程序，批次报告按它归档（执行侧只用于落报告）
  const MACHINE_APP_ID = 'MACHINE|all';

  // 删前备份偏好（HiBit §H1 还原包）。取「显式关过才算关」以外的最保守解：
  // 读不到 / 读失败一律按关，因为开备份会带来几百 MB 落盘，猜错方向的代价不对称。
  const BACKUP_PREF_KEY = 'trim.residue.backupPack';
  function readBackupPref() {
    try { return localStorage.getItem(BACKUP_PREF_KEY) === '1'; } catch (e) { return false; }
  }

  function esc(s) { return window.ds.esc(s); }
  function fmtSizeKb(kb) {
    kb = Number(kb) || 0;
    if (kb <= 0) return '—';
    const units = ['KB', 'MB', 'GB'];
    let v = kb, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
  }

  const KIND_LABEL = {
    reg_key: '注册表', folder: '目录', file: '文件', shortcut: '快捷方式',
  };
  const CONF_LABEL = { high: '高置信', medium: '中置信', low: '低置信（建议人工核对）' };

  // ==================== 应用图标（用户要求 2026-09-28：名称前显示真实图标） ====================
  // 复用 paths:file-icon / paths:app-icon（shellicon 提取）。两层缓存：
  // ① 内存 Map（会话内）② localStorage 落盘（跨会话，U-3；总量 1MB 上限，
  // 超限按 LRU 丢弃）。缓存键 = id|version：同 id 升级后版本变化自动失效。
  // 不放后端缓存的原因：paths 通道是通用面（路径绑定/残留扫描共用），
  // 在命令里注入按应用维度的缓存语义会污染其它调用方。
  const ICON_CACHE_KEY = 'uninstall-icon-cache-v1';
  const ICON_CACHE_MAX = 1 << 20;   // 落盘总量上限（dataURL 粗算与原图 1:1.37）
  const ICON_CACHE_ENTRY_MAX = 32 * 1024; // 单条超限不落盘（大图实时取）
  const ICON_CONCURRENCY = 4;       // 并发提取上限（shellicon 提取有进程外开销，4 路已打满）

  const iconCache = loadIconCache(); // key=id|version -> dataUrl | ''（失败也缓存，避免重扫重试）

  function loadIconCache() {
    try {
      const o = JSON.parse(localStorage.getItem(ICON_CACHE_KEY));
      if (o && typeof o === 'object' && !Array.isArray(o)) return new Map(Object.entries(o));
    } catch (_) { /* 损坏即重建 */ }
    return new Map();
  }

  // 持久化：超限丢最旧（Map 迭代序 = 插入序，命中即重插实现 LRU）；配额不足静默放弃
  function persistIconCache() {
    try {
      const out = {};
      let total = 0;
      const entries = [];
      for (const [k, v] of iconCache) {
        if (typeof v === 'string' && v.length && v.length <= ICON_CACHE_ENTRY_MAX) {
          entries.push([k, v]);
          total += v.length;
        }
      }
      while (entries.length && total > ICON_CACHE_MAX) {
        const [, v] = entries.shift();
        total -= v.length;
      }
      for (const [k, v] of entries) out[k] = v;
      localStorage.setItem(ICON_CACHE_KEY, JSON.stringify(out));
    } catch (_) { /* 配额不足不影响功能 */ }
  }

  // B7：安装日期格子的悬停说明。最近运行只在真拿得到时出现——
  // Prefetch 目录非提权读不到，此时不显示也不猜「从未运行」。
  function installDateTip(a) {
    let tip = '注册表键最后写入时间，近似安装日期';
    if (a.lastRunMs) {
      const d = new Date(a.lastRunMs);
      const pad = (n) => String(n).padStart(2, '0');
      tip += '；主程序最近运行 ' + d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
        + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + '（Prefetch）';
    }
    return tip;
  }

  // B6：EstimatedSize 是厂商自愿写的字段，缺失就不是 0。缺的地方按安装目录估一次，
  // 标「估算」并在截断时说明不精确；后台懒取，不拖慢首屏（与图标同一套路）。
  async function fillMissingSizes() {
    const need = apps.filter((a) => !a.estimatedSizeKb && a.installLocation);
    for (const a of need) {
      const cell = document.querySelector(`[data-un-size="${CSS.escape(a.id)}"]`);
      if (!cell) continue;
      try {
        const r = await window.api.uninstall.dirSize(a.installLocation);
        if (!r || !r.success || !r.data) continue;
        if (!r.data.sizeKb) continue;
        const stillThere = document.querySelector(`[data-un-size="${CSS.escape(a.id)}"]`);
        if (!stillThere) return; // 列表已重绘，旧结果不再回写
        stillThere.textContent = '≈' + fmtSizeKb(r.data.sizeKb);
        // HiBit §H5：命名数据流（ADS）不计入本体体积，单独在提示里交代。
        // 它解释的是「为什么删完释放的比显示的多」——下载来源标记 Zone.Identifier 就住在这里
        stillThere.setAttribute('data-tip', '厂商未写 EstimatedSize，按安装目录大小估算'
          + (r.data.partial ? '（文件数或层级触顶，实际可能更大）' : '')
          + (Number(r.data.adsStreams) > 0
            ? `；另含 ${r.data.adsStreams} 条备用数据流约 ${fmtSizeKb(Math.ceil(Number(r.data.adsBytes) / 1024))}（不计入上面的数）`
            : ''));
      } catch (e) { /* 估不出来就留空位，不编一个数 */ }
    }
  }

  const iconCacheKey = (a) => `${a.id}|${a.displayVersion || ''}`;

  // 图标源优先级：Appx Logo（.png 直接读图，U-3）→ displayIcon（剥 ,索引 后缀）→
  // 安装目录图标（app-icon 对目录取壳图标）。
  function iconSourcePaths(a) {
    const out = [];
    if (a.logoPath) out.push({ kind: 'png', path: a.logoPath });
    const di = String(a.displayIcon || '').split(',')[0].trim();
    if (di) out.push({ kind: 'file', path: di });
    if (a.installLocation) out.push({ kind: 'dir', path: a.installLocation });
    // 第四源：桌面/开始菜单的 .lnk（后端按精确同名匹配好）。DisplayIcon 常指向已搬走的路径，
    // 而快捷方式本身带着正确图标 —— SHGetFileInfoW 会顺着 .lnk 解析到目标图标。
    if (a.shortcutPath) out.push({ kind: 'file', path: a.shortcutPath });
    return out;
  }

  async function fetchIcon(app) {
    const key = iconCacheKey(app);
    if (iconCache.has(key)) {
      // LRU touch：命中即重插到 Map 尾部
      const v = iconCache.get(key);
      iconCache.delete(key);
      iconCache.set(key, v);
      return v;
    }
    let url = '';
    for (const src of iconSourcePaths(app)) {
      try {
        const resp = src.kind === 'png'
          ? await window.api.uninstall.appxLogo(src.path)
          : src.kind === 'file'
            ? await window.api.paths.fileIcon(src.path)
            : await window.api.paths.appIcon(src.path, null);
        if (resp && resp.success && resp.dataUrl) { url = resp.dataUrl; break; }
      } catch (e) { /* 图标失败不阻塞列表，占位兜底 */ }
    }
    iconCache.set(key, url);
    return url;
  }

  // 渲染完成后并发补图标（U-3：4 路并发池，shellicon/读图都是进程外或 IO 开销，
  // 串行 83 个约秒级 → 并发后亚秒；并发太高会打爆 shell 提取，不设更高）。
  // 用 dataset 定位单元格：渲染期间用户翻页/重扫时旧节点已 detached，直接跳过。
  async function hydrateIcons() {
    const pending = apps.filter((a) => {
      const cell = document.querySelector(`[data-un-icon="${CSS.escape(a.id)}"]`);
      return cell && cell.dataset.loaded !== '1';
    });
    let idx = 0;
    const worker = async () => {
      while (idx < pending.length) {
        const app = pending[idx++];
        const cell = document.querySelector(`[data-un-icon="${CSS.escape(app.id)}"]`);
        if (!cell || cell.dataset.loaded === '1') continue;
        const url = await fetchIcon(app);
        cell.dataset.loaded = '1';
        cell.innerHTML = url
          ? `<img src="${window.ds.escAttr(url)}" alt="" draggable="false">`
          : '<span class="un-icon-fallback">▣</span>';
      }
    };
    await Promise.all(Array.from({ length: Math.min(ICON_CONCURRENCY, pending.length) }, worker));
    persistIconCache();
  }

  // ==================== 程序列表 ====================
  async function loadApps() {
    const listEl = document.getElementById('uninstallList');
    if (enumerating) return;
    enumerating = true;
    // 自我安慰式进度：枚举期间进度条爬升封顶 99%，完成即 100% 收尾
    startFakeProgress(currentScope === 'windows' ? '正在枚举 Windows 应用…' : '正在枚举已安装程序…');
    listEl.innerHTML = '<div class="finder-empty">正在枚举…</div>';
    try {
      const resp = await window.api.uninstall.list(currentScope);
      if (!resp.success) throw new Error(resp.message || '枚举失败');
      apps = resp.data.apps || [];
      if (!apps.length) {
        listEl.innerHTML = '<div class="finder-empty">没有枚举到已安装程序</div>';
        return;
      }
      listEl.innerHTML = currentScope === 'windows' ? renderWindowsApps() : renderWin32Apps();
      hydrateIcons();
      // 体积补全要逐目录读盘，放首屏之后跑，不阻塞列表出现。
      if (currentScope !== 'windows') fillMissingSizes();
    } catch (e) {
      listEl.innerHTML = `<div class="finder-empty">枚举失败：${esc(String(e.message || e))}</div>`;
      window.app?.toast?.('error', '枚举失败: ' + (e.message || e));
    } finally {
      finishFakeProgress();
      enumerating = false;
    }
  }

  // P1-D6（2026-10-01）：修改/修复按钮灰化口径——
  //   修改：要有 ModifyPath 且未声明 NoModify；修复：要有 ModifyPath 且未声明 NoRepair。
  //   两类"灰"必须分清：没命令行是"我们没得跑"，声明位是"程序自己说不行"。
  function modifyBtnAttr(a) {
    if (!a.modifyPath) return ' disabled data-tip="没有 ModifyPath，无法执行修改/修复"';
    return '';
  }
  function noModifyAttr(a) {
    return a.noModify ? ' disabled data-tip="该程序声明不支持更改（NoModify）"' : '';
  }
  function noRepairAttr(a) {
    return a.noRepair ? ' disabled data-tip="该程序声明不支持修复（NoRepair）"' : '';
  }
  // P1-D6：NoRemove=1 是 ARP 声明「不许卸载」，与"没有 UninstallString"是两回事，
  // 文案分开写，别让用户以为是我们没做。
  function noRemoveAttr(a) {
    if (!a.uninstallString) return ' disabled data-tip="没有 UninstallString，无法调用原厂卸载器"';
    if (a.noRemove) return ' disabled data-tip="该程序声明不可卸载（NoRemove），系统安装策略禁止移除"';
    return '';
  }

  // 用户应用（传统 Win32）：三个卸载注册表根合并，HiBit「程序名」83 项的口径
  function renderWin32Apps() {
    const rows = apps.map((a) => `
      <tr>
        <td><div class="finder-cell"><span class="un-icon" data-un-icon="${esc(a.id)}"></span><span class="finder-name-text">${esc(a.displayName)}</span></div></td>
        <td class="finder-col-size" style="width:180px"><span class="finder-name-text" style="opacity:.7">${esc(a.publisher || '—')}</span></td>
        <td class="finder-col-size" style="width:110px"><span class="finder-name-text" style="opacity:.7">${esc(a.displayVersion || '—')}</span></td>
        <td class="finder-col-size" style="width:90px"><span data-un-size="${esc(a.id)}">${fmtSizeKb(a.estimatedSizeKb)}</span></td>
        <td class="finder-col-size" style="width:110px"><span class="finder-name-text" style="opacity:.7" data-tip="${esc(installDateTip(a))}">${esc(a.installDate || '—')}</span></td>
        <td class="finder-col-size" style="width:210px">
          <button class="btn btn-secondary btn-small" data-un-app="${esc(a.id)}"${noRemoveAttr(a)}>卸载</button>
          <button class="btn btn-secondary btn-small" data-un-modify="${esc(a.id)}"${modifyBtnAttr(a)}${noModifyAttr(a)}>修改</button>
          <button class="btn btn-secondary btn-small" data-un-repair="${esc(a.id)}"${modifyBtnAttr(a)}${noRepairAttr(a)}>修复</button>
        </td>
      </tr>`).join('');
    return `
      <table class="finder-table">
        <thead><tr><th>程序<span class="page-summary">共 ${apps.length} 个应用</span></th><th class="finder-col-size" style="width:180px">发行商</th><th class="finder-col-size" style="width:110px">版本</th><th class="finder-col-size" style="width:90px">大小</th><th class="finder-col-size" style="width:110px">安装日期</th><th class="finder-col-size" style="width:210px">操作</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  // Windows 应用（Appx）：按 HiBit 口径分「第三方应用 / Windows 应用」两组
  function renderWindowsApps() {
    const third = apps.filter((a) => a.group === 'third');
    const sys = apps.filter((a) => a.group !== 'third');
    const section = (title, list, withTotal) => {
      if (!list.length) return '';
      // 卸载按钮的禁用属性。三类"不可卸载"要说清差别：NonRemovable 是系统声明不许移除，
  // staged / 全用户预配是**当前用户删不掉**（Remove-AppxPackage 是用户语义），
  // 混成一句会让用户以为我们只是没做这个功能。
  function uninstallBlockAttr(a) {
    if (!a || a.removable === false) {
      const reason = a && a.reason ? a.reason : '系统声明的不可移除包';
      return ` disabled data-tip="${esc(reason)}"`;
    }
    return '';
  }

  const rows = list.map((a) => `
        <tr>
          <td><div class="finder-cell"><span class="un-icon" data-un-icon="${esc(a.id)}"></span><span class="finder-name-text">${esc(a.displayName)}</span></div></td>
          <td class="finder-col-size" style="width:190px"><span class="finder-name-text" style="opacity:.7">${esc(a.publisher || '—')}</span></td>
          <td class="finder-col-size" style="width:130px"><span class="finder-name-text" style="opacity:.7">${esc(a.displayVersion || '—')}</span></td>
          <td class="finder-col-size" style="width:150px">
            <button class="btn btn-secondary btn-small" data-un-app="${esc(a.id)}"${uninstallBlockAttr(a)}>卸载</button>
          </td>
        </tr>`).join('');
      return `<div class="finder-group-header"><span>${title} · ${list.length} 项</span></div>
        <table class="finder-table">
          <thead><tr><th>应用名${withTotal ? `<span class="page-summary">共 ${apps.length} 个应用</span>` : ''}</th><th class="finder-col-size" style="width:190px">发布者</th><th class="finder-col-size" style="width:130px">版本</th><th class="finder-col-size" style="width:150px">操作</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`;
    };
    // 总数只落在第一张表的表头：两组都在时归「第三方应用」，第三方为空时归「Windows 应用」
    return section('第三方应用', third, true) + section('Windows 应用', sys, !third.length);
  }

  // ==================== 卸载 ====================
  async function runUninstall(appId) {
    const app = apps.find((a) => a.id === appId);
    if (!app || running) return;
    const isAppx = appId.startsWith('APPX|');
    // B1（2026-09-28 二轮拍板）：静默勾选框已删，静默优先是后端默认行为——
    // 前端不再传 silent 参数，卸载方式由后端按安装器类型裁决并经 usedSilent/fellBack 回传。
    const ok = await window.app?.confirmDanger?.(
      '确认卸载',
      isAppx
        ? `将从当前用户移除 Windows 应用「${app.displayName}」（Remove-AppxPackage，不弹确认界面）。`
        : `将卸载「${app.displayName}」：支持静默的安装器（msi/inno/nsis）先尝试静默卸载，否则自动弹出原厂卸载界面，按其提示操作。`,
      '开始卸载',
      '取消',
      isAppx
        ? '移除后其 %LOCALAPPDATA%\\Packages\\<包名> 应用数据将进入残留扫描候选，可一并清理（进回收站，可还原）。'
        : '卸载是不可逆操作；完成后 Trim 会自动复查卸载结果并提供残留扫描。'
    );
    if (!ok) return;
    running = true;
    startFakeProgress(isAppx ? '正在移除 Windows 应用…' : '卸载器运行中…等待卸载完成');
    try {
      const resp = await window.api.uninstall.run(appId);
      if (!resp.success) throw new Error(resp.message || '卸载失败');
      const d = resp.data || {};
      // 退出码语义后端早就算好了（classify_exit），但前端一直没用：1602 取消与 1618
      // 并发都只被笼统播报成「仍在列表里」，用户不知道该等一会儿还是再点一次。
      // 有界重试仍按裁定不做（要真机 MSI/NSIS 样本才定策略），这里只把已知语义说清楚。
      const meaning = d.exitMeaning ? `（退出码 ${d.exitCode}：${d.exitMeaning}）` : '';
      if (isAppx) {
        window.app?.toast?.('success', `「${app.displayName}」已移除`);
      } else if (d.stillListed) {
        window.app?.toast?.('warning', `卸载器已退出，但该程序仍在卸载列表中${meaning}。可稍后再试一次卸载`);
      } else if (Number(d.exitCode) === 3010) {
        window.app?.toast?.('success', '卸载完成，需重启系统以完成清理（重启前部分残留可能仍在）');
      } else if (d.fellBack) {
        window.app?.toast?.('success', '静默卸载未完成，已回退原厂卸载界面并执行完毕，可以继续扫描残留');
      } else if (d.usedSilent) {
        window.app?.toast?.('success', '静默卸载完成，可以继续扫描残留');
      } else {
        window.app?.toast?.('success', '卸载完成，可以继续扫描残留');
      }
      await loadApps();
      // 卸载完成后自动扫三类残留（U-4 拍板 2026-09-28：Appx 移除后 Packages 数据也进扫描）
      currentAppId = appId;
      await scanAllResidue();
    } catch (e) {
      // P1-D1（2026-10-01）：对齐 Geek msgUninstallFailed 的语义——失败后一句话把两件事
      // 说清：卸载没成 + 已存在的残留仍可清。只改呈现：不自动扫、不预勾选任何删除项，
      // 用户仍要点「重新扫描」并逐项确认（与成功路径同一套候选/勾选/确认链）。
      window.app?.toast?.('error', '卸载失败: ' + (e.message || e));
      window.app?.toast?.('info', '卸载程序没有执行完成；它已存在的文件与注册表项不会被自动改动——可点「重新扫描」清点残留后逐项确认删除');
    } finally {
      finishFakeProgress();
      running = false;
    }
  }

  // P1-D6（2026-10-01）：修改 / 修复。二者执行的是同一条 ModifyPath（ARP 口径，
  // MSI 产品会弹维护对话框再分项），NoModify/NoRepair 由后端执行时复判——
  // 前端灰化只是入口提示，清单可能是旧快照。这里只做确认与结果播报。
  async function runModify(appId, mode) {
    if (running) return;
    const app = apps.find((a) => a.id === appId);
    if (!app) return;
    const label = mode === 'repair' ? '修复' : '修改';
    const ok = await window.app?.confirmDanger?.(
      `确认${label}`,
      `将打开「${app.displayName}」自带的${label}程序（来自注册表 ModifyPath），按其界面提示操作。`,
      `开始${label}`,
      '取消'
    );
    if (!ok) return;
    running = true;
    startFakeProgress(`正在启动${label}程序…`);
    try {
      const resp = await window.api.uninstall.modify(appId, mode);
      if (!resp.success) throw new Error(resp.message || `${label}失败`);
      const code = resp.data && resp.data.exitCode;
      window.app?.toast?.(code === 0 ? 'success' : 'info', `${label}程序已退出（退出码 ${code ?? '未知'}）`);
    } catch (e) {
      window.app?.toast?.('error', `${label}失败: ` + (e.message || e));
    } finally {
      finishFakeProgress();
      running = false;
    }
  }

  // ==================== P1-B3 重启后删（2026-10-01 拍板） ====================
  // 四条硬约束见 uninstall.rs 同名段：明示+单独确认 / 只限回收站失败文件项 /
  // 可撤回 / 待删清单可见。这里没有任何静默登记路径——按钮必须由一次真实的
  // 清理失败结果驱动，登记前还有单独的确认框。
  let pendingFailedTargets = [];

  function updatePendingButtons(failedFiles) {
    const addBtn = document.getElementById('residueBtnPending');
    const revBtn = document.getElementById('residueBtnPendingRevoke');
    if (addBtn) {
      if (Array.isArray(failedFiles)) pendingFailedTargets = failedFiles;
      addBtn.style.display = pendingFailedTargets.length ? '' : 'none';
      addBtn.textContent = `重启后删除失败的 ${pendingFailedTargets.length} 项…`;
      addBtn.disabled = !pendingFailedTargets.length;
    }
    if (revBtn) {
      window.api.uninstall.pendingList().then((r) => {
        const entries = (r && r.success && r.data && r.data.entries) || [];
        const degraded = !!(r && r.success && r.data && r.data.degraded);
        const n = entries.filter((e) => e.status === 'pending').length;
        if (degraded) {
          // M-6（2026-10-03 L3）：台账损坏 = 撤回凭据不可信。
          // 不能隐藏按钮（那样用户根本不知道有东西待删、PFRO 里还挂着）；
          // 置灰 + data-tip 说明，与「真的没有待删项」区分开。
          revBtn.style.display = '';
          revBtn.disabled = true;
          revBtn.textContent = '重启后删台账已损坏';
          revBtn.setAttribute(
            'data-tip',
            '待删清单文件损坏，无法确认哪些条目仍挂起；PFRO 里的登记可能仍会在下次重启时执行。'
          );
        } else {
          revBtn.style.display = n ? '' : 'none';
          revBtn.disabled = !n;
          revBtn.textContent = `撤回重启后删（${n} 项）`;
        }
      }).catch(() => {});
    }
  }

  async function addPendingDeletes() {
    if (!pendingFailedTargets.length) return;
    const ok = await window.app?.confirmDanger?.(
      '登记重启后删除',
      `把 ${pendingFailedTargets.length} 个回收站删不掉的文件登记为「下次重启时删除」。这是永久删除：不进回收站、无法还原；重启前可撤回。目录不支持该机制，登记时会被跳过。`,
      '登记',
      '取消',
      '将写入系统 PendingFileRenameOperations，重启动作由系统在会话管理器阶段执行，Trim 不参与那一步。'
    );
    if (!ok) return;
    try {
      const resp = await window.api.uninstall.pendingAdd(pendingFailedTargets);
      if (!resp.success) throw new Error(resp.message || '登记失败');
      const d = resp.data || {};
      window.app?.toast?.(d.added ? 'success' : 'info',
        d.added
          ? `已登记 ${d.added} 项，将在下次重启时永久删除（重启前可撤回）`
          : '没有新登记项（可能都已登记过或目标已不在）');
      pendingFailedTargets = [];
      updatePendingButtons([]);
    } catch (e) {
      window.app?.toast?.('error', '登记失败: ' + (e.message || e));
    }
  }

  async function revokePendingDeletes() {
    const ok = await window.app?.confirmDanger?.(
      '撤回重启后删除',
      '将把已登记的「重启后删除」条目从系统中摘除：相关文件不会被删除，保持原样。',
      '撤回全部',
      '取消'
    );
    if (!ok) return;
    try {
      const resp = await window.api.uninstall.pendingRevoke();
      if (!resp.success) throw new Error(resp.message || '撤回失败');
      window.app?.toast?.('success', `已撤回 ${resp.data.revoked} 项登记，相关文件不会被删除`);
      updatePendingButtons([]);
    } catch (e) {
      window.app?.toast?.('error', '撤回失败: ' + (e.message || e));
    }
  }

  function setBusy(busy, label) {
    const overlay = document.getElementById('uninstallBusy');
    if (overlay) {
      overlay.style.display = busy ? 'block' : 'none';
      if (label) overlay.querySelector('.progress-label').textContent = label;
    }
  }

  // ==================== 自我安慰式进度（用户拍板 2026-09-28） ====================
  // 「Windows应用」枚举（Get-AppxPackage 子进程）耗时秒级且无真百分比——
  // 纯文字「正在枚举…」观感是卡死。改为进度条：从 5% 缓慢爬升封顶 99%，
  // 完成即 100% 收尾隐藏。卸载等待也复用同一条（卸载器耗时未知，同口径）。
  let busyTicker = null;

  function startFakeProgress(label) {
    stopFakeProgress();
    const overlay = document.getElementById('uninstallBusy');
    if (!overlay) return;
    overlay.style.display = 'block';
    if (label) overlay.querySelector('.progress-label').textContent = label;
    const fill = overlay.querySelector('.progress-fill');
    let v = 5;
    busyTicker = setInterval(() => {
      v = Math.min(99, v + Math.max(0.3, (99 - v) * 0.02));
      if (fill) fill.style.width = v + '%';
    }, 350);
  }

  function finishFakeProgress() {
    stopFakeProgress();
    const fill = document.querySelector('#uninstallBusy .progress-fill');
    if (fill) fill.style.width = '100%';
    setTimeout(() => {
      const overlay = document.getElementById('uninstallBusy');
      if (overlay) overlay.style.display = 'none';
      if (fill) fill.style.width = '0%';
    }, 350);
  }

  function stopFakeProgress() {
    if (busyTicker) { clearInterval(busyTicker); busyTicker = null; }
  }

  // ==================== 残留扫描（一个入口，三条链） ====================
  // 面板标题统一叫「残留扫描」，内部按证据来源分三组：
  //   程序残留     —— 规则库命中，要有选中或刚卸载的那个程序；
  //   失效残留     —— 全机扫描，判据只有一条：卸载项/App Paths 里记着的落点文件已不存在，
  //                   不要求本机有卸载记录（用户拍板 2026-09-28）。服务与设备刻意不扫：
  //                   判据虽成立，但删除要提权走 SCM/SetupAPI，我们缺这块实操经验；
  //   卸载遗留     —— 仍要「本机确实卸载过它」这条所有权事实，精确同名目录本身不是证据；
  //                   厂商配置键走「卸载前基线 → 卸载后差分」，还要键名与这程序的 name/发行商/
  //                   安装目录名互含才算到它头上（HiBit §9.1，两条证据缺一不可）。
  // 三组共用同一份快照（后端按 origin 分桶存）与同一条执行链，所以先扫哪组都不会让
  // 另一组的勾选项在执行时被快照闸判成"已过期"。
  async function scanAllResidue() {
    const panel = document.getElementById('residuePanel');
    const box = document.getElementById('residueList');
    panel.style.display = 'block';
    box.innerHTML = '<div class="finder-empty">正在扫描三类残留（规则库 / 失效登记 / 卸载记录）…</div>';
    // U-8 感知修复：面板在长列表下方，不滚动就等于"没弹出"
    // 审查 L16 / v2 批次A2：CSS 的 prefers-reduced-motion 通配归零管不到 JS 传进去的
    // scroll 选项，必须在这里自己求值——否则系统关掉动画的用户仍会被这段 smooth 滚动
    // 推着走（与 app.js toggleNavSub 同口径）。
    const reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    panel.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    const app = currentAppId && currentAppId !== MACHINE_APP_ID ? currentAppId : '';
    const fail = (e) => ({ success: false, message: String((e && e.message) || e) });
    const [rApp, rDead, rOrphan] = await Promise.all([
      app ? window.api.uninstall.residueScan(app).catch(fail) : Promise.resolve(null),
      window.api.uninstall.deadScan().catch(fail),
      window.api.uninstall.orphanScan().catch(fail),
    ]);
    const groups = [];
    if (!app) {
      groups.push({ title: '程序残留（规则库）', rows: [], hint: '未选中程序。在上方列表点一行再扫描，可带上它的规则库残留。' });
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
      // 这一组拒绝扫描是**正确行为**（档案为空时拿空集会被读成"这台机器没有遗留"），
      // 所以按组的说明行呈现，不再让整页扫描失败
      groups.push({ title: '卸载遗留 · 按本机卸载记录', rows: [], hint: ((rOrphan && rOrphan.message) || '本组未执行') });
    }
    scanGroups = groups;
    findings = groups.reduce((acc, g) => acc.concat(g.rows), []);
    // 勾选初值在渲染前定好：只展示不给删的行永远不该被勾上
    findings.forEach((f) => {
      f._checked = f.deleteCapable !== false && !!f.defaultChecked;
    });
    document.getElementById('residueTitle').textContent = '残留扫描';
    renderResidue();
    const n = findings.length;
    const notes = (rDead && rDead.success && rDead.data.notes && rDead.data.notes.length) ? rDead.data.notes[0] : '';
    window.app?.toast?.(n ? 'info' : 'success',
      n ? `共 ${n} 项候选，一律未自动勾选，请逐项确认` : (notes || '三类扫描都没有发现残留'));
  }

  const DEAD_CLASS_TITLE = {
    uninstall: '失效卸载项（可删该注册表键）',
    appPaths: '失效 App Paths（可删该注册表键）',
  };

  function groupHtml(g) {
    let h = `<div class="finder-group-header" style="margin-top:14px"><span>${esc(g.title)} · ${g.rows.length} 项</span></div>`;
    if (!g.rows.length) return h + `<div class="finder-empty">${esc(g.hint || '本组没有候选。')}</div>`;
    if (g.byClass) {
      for (const cls of ['uninstall', 'appPaths']) {
        const rows = g.rows.filter((f) => f.deadClass === cls);
        if (rows.length) h += residueTableHtml(DEAD_CLASS_TITLE[cls] || cls, rows);
      }
      return h;
    }
    const regs = g.rows.filter((f) => f.kind === 'reg_key' || f.kind === 'reg_value');
    const files = g.rows.filter((f) => f.kind !== 'reg_key' && f.kind !== 'reg_value');
    if (regs.length) h += residueTableHtml('注册表', regs);
    if (files.length) h += residueTableHtml('文件与目录', files);
    return h;
  }

  function residueTableHtml(title, rows) {
    let h = `<div class="finder-group-header" style="margin-top:8px;font-size:12px;opacity:.8"><span>${esc(title)} · ${rows.length} 项</span></div>`;
    h += '<table class="finder-table"><thead><tr><th style="width:34px"></th><th>目标</th><th style="width:110px">置信度</th><th style="width:220px">判定原因</th></tr></thead><tbody>';
    for (const f of rows) {
      const i = findings.indexOf(f);
      const cell = f.deleteCapable === false
        ? '<span class="finder-name-text" style="opacity:.5" data-tip="本链只登记、不删除">—</span>'
        : `<span class="checkbox ${f._checked ? 'checked' : ''}" data-rcheck="${i}"></span>`;
      // 应用数据遗留的处置出口：所有权判定可能有误（同名另一款软件、用户自己放的目录），
      // 必须能把某个历史 owner 永久排除，而不是每次扫描都重复看到同一条
      const ignoreBtn = f.origin === 'orphan'
        ? `<button class="btn btn-secondary" style="margin-left:8px;padding:2px 8px;font-size:12px" data-orphan-ignore="${i}" data-tip="此后不再按这条卸载记录提示遗留数据（只影响应用数据遗留这一组，不动残留规则库）">不再提示该程序</button>`
        : '';
      const tested = (f.testedPaths && f.testedPaths.length) ? f.testedPaths.join('\n') : f.target;
      // C4：判定依据按离散贡献项逐条给（后端只产事实、不产分数），一行一条。
      const contribs = f.contribs || [];
      const whyTip = contribs.length
        ? ` data-tip="${esc(contribs.map((c) => '· ' + (c.text || '')).join('\n'))}"`
        : '';
      const whyHint = contribs.length
        ? `<span class="finder-name-text" style="opacity:.5;font-size:11px">· 依据 ${contribs.length} 条</span>`
        : '';
      h += `<tr class="${f._checked ? 'finder-row-selected' : ''}">
          <td>${cell}</td>
          <td><div class="finder-cell"><span class="finder-path-text" data-tip="${esc(tested)}">${esc(f.target)}</span></div></td>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.75">${CONF_LABEL[f.confidence] || f.confidence || '—'}</span></td>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.75"${whyTip}>${esc(f.reason || '')}</span>${whyHint}${ignoreBtn}</td>
        </tr>`;
    }
    return h + '</tbody></table>';
  }

  function renderResidue() {
    const box = document.getElementById('residueList');
    if (!findings.length && !scanGroups.length) {
      box.innerHTML = '<div class="finder-empty">未发现残留。程序卸载得很干净。</div>';
      updateResidueButtons();
      return;
    }
    box.innerHTML = scanGroups.map(groupHtml).join('');
    updateResidueButtons();
  }

  async function ignoreOrphanOwner(f) {
    try {
      const resp = await window.api.uninstall.orphanIgnore(f.ownerAppId, f.ownerName || '');
      if (!resp || !resp.success) throw new Error((resp && resp.message) || '写入忽略记录失败');
      window.app?.toast?.('success', `已不再提示「${esc(f.ownerName || '')}」的遗留数据`);
      await scanAllResidue();
    } catch (e) {
      window.app?.toast?.('error', '忽略失败: ' + (e && e.message ? e.message : String(e)));
    }
  }
  function onResidueClick(e) {
    const ign = e.target.closest('[data-orphan-ignore]');
    if (ign) {
      const target = findings[Number(ign.dataset.orphanIgnore)];
      if (target) ignoreOrphanOwner(target);
      return;
    }
    const t = e.target.closest('[data-rcheck]');
    if (!t) return;
    // 勾选按 findings 全局下标寻址：面板现在有多组多表，段内序号会跨表串位
    const f = findings[Number(t.dataset.rcheck)];
    if (!f || f.deleteCapable === false) return;
    f._checked = !f._checked;
    t.classList.toggle('checked', f._checked);
    t.closest('tr').classList.toggle('finder-row-selected', f._checked);
    updateResidueButtons();
  }

  function updateResidueButtons() {
    const any = findings.some((f) => f._checked);
    document.getElementById('residueBtnClean').disabled = !any;
  }

  // ==================== 残留清理 ====================
  async function cleanResidue() {
    const picked = findings.filter((f) => f._checked);
    if (!picked.length || running) return;
    const ok = await window.app?.confirmDanger?.(
      '确认清理残留',
      `将删除选中的 ${picked.length} 项残留。文件与目录移入回收站（可还原）；注册表项删除前自动导出备份。${readBackupPref() ? '已开启删前备份：选中内容会先打进本机还原包，之后可整批写回原位置。' : ''}`,
      '开始清理',
      '取消',
      '低置信项为名称启发式结果，请确认路径确实属于已卸载的程序再勾选。'
    );
    if (!ok) {
      // P1-D2（2026-10-01）：对齐 Geek msgCancelWizard——取消时把「已发现的候选不会被删」
      // 说明白，N 取当前面板的真实候选数（含未勾选的展示行，而不是只数勾选项：
      // 用户取消时关心的是"整批都不会动"）。取消路径到此为止，之后没有任何删除调用。
      window.app?.toast?.('info', `已取消：本次已发现的 ${findings.length} 项候选不会被删除，内容保持原样`);
      return;
    }
    running = true;
    setBusy(true, '正在清理残留…');
    startFakeProgress('正在清理残留…');
    try {
      const resp = await window.api.uninstall.residueExecute(
        currentAppId,
        picked.map((f) => ({ kind: f.kind, target: f.target })),
        readBackupPref()
      );
      if (!resp.success) throw new Error(resp.message || '残留清理失败');
      const d = resp.data || {};
      // 还原包结果要说清：勾了备份却没成（收尾失败）时必须当场讲，不能等用户去还原才发现
      const pack = d.restorePack;
      if (pack && pack.error) {
        window.app?.toast?.('error', `还原包写入失败：${pack.error}（文件已删除，内容无法还原，回收站仍可查看）`);
      } else if (pack) {
        window.app?.log?.('info', `还原包已生成：${pack.files} 个文件 / ${pack.dirs} 个目录 / ${(pack.bytes / 1048576).toFixed(1)} MB（${pack.id}）`);
      }
      const okCount = Number(d.okCount) || 0;
      const failCount = Number(d.failCount) || 0;
      if (failCount > 0) {
        window.app?.toast?.('warning', `残留清理完成：${okCount} 项成功，${failCount} 项失败（详见报告）`);
      } else {
        window.app?.toast?.('success', `残留清理完成：${okCount} 项已处理`);
      }
      // 成功项从面板移除，重渲染
      const done = new Set((d.details || []).filter((x) => x.status === 'ok').map((x) => x.kind + '|' + x.target));
      findings = findings.filter((f) => !done.has(f.kind + '|' + f.target));
      renderResidue();
      await loadApps();
      // P1-B3（2026-10-01）：失败的文件项（被占用/无权限）可显式降级为重启后删。
      // 按钮只是入口，登记前还有单独确认框；只送文件，目录项后端会拒（PFRO 对非空目录不可靠）。
      const failedFiles = (d.details || [])
        .filter((x) => x.status !== 'ok' && x.kind === 'file')
        .map((x) => x.target);
      updatePendingButtons(failedFiles);
    } catch (e) {
      window.app?.toast?.('error', '残留清理失败: ' + (e.message || e));
    } finally {
      stopFakeProgress();
      setBusy(false);
      running = false;
    }
  }

  // ==================== U-6 批次报告查看 ====================

  function closeReportModal() {
    document.getElementById('unReportBackdrop')?.remove();
  }

  async function renderReportList(ctrl) {
    const body = ctrl.body;
    let resp;
    try {
      resp = await window.api.uninstall.reportList();
    } catch (e) {
      if (document.body.contains(body)) body.innerHTML = `<div class="finder-empty">报告读取失败: ${esc(e.message || e)}</div>`;
      return;
    }
    if (!document.body.contains(body)) return;
    const reports = (resp && resp.success && resp.data && resp.data.reports) || [];
    if (!reports.length) {
      body.innerHTML = '<div class="finder-empty">还没有残留清理报告。执行一次「删除选中残留」后会自动生成。</div>';
      return;
    }
    body.innerHTML = `<table class="finder-table"><thead><tr><th>时间</th><th style="width:230px">目标程序（卸载键）</th><th class="finder-col-size" style="width:170px">成功/失败/跳过</th><th class="finder-col-size" style="width:80px">明细</th></tr></thead><tbody>${
      reports.map((r, i) => `
        <tr>
          <td><span class="finder-name-text" style="opacity:.8">${esc(r.time || r.batchId)}</span></td>
          <td><span class="finder-name-text" style="opacity:.8" data-tip="${esc(r.appId || '')}">${esc(r.appId || '—')}</span></td>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.8">${r.okCount} / ${r.failCount} / ${r.skipCount}</span></td>
          <td class="finder-col-size"><button class="fileclean-preview-btn" data-report-view="${i}" type="button">查看</button></td>
        </tr>`).join('')
    }</tbody></table>`;
    body.querySelectorAll('[data-report-view]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const r = reports[+btn.getAttribute('data-report-view')];
        if (r) openReportDetail(r.batchId, ctrl);
      });
    });
  }

  async function openReportDetail(batchId, ctrl) {
    let resp;
    try {
      resp = await window.api.uninstall.reportGet(batchId);
    } catch (e) {
      window.app?.toast?.('error', '报告读取失败: ' + (e.message || e));
      return;
    }
    if (!resp || !resp.success) {
      window.app?.toast?.('error', (resp && resp.message) || '报告读取失败');
      return;
    }
    const body = ctrl.body;
    if (!document.body.contains(body)) return;
    const data = resp.data || {};
    const details = Array.isArray(data.details) ? data.details : [];
    const statusLabel = { ok: '成功', fail: '失败', skip: '跳过' };
    body.innerHTML = `
      <div class="finder-group-header"><span>批次 ${esc(batchId)} · ${esc(data.appId || '')}</span></div>
      ${details.length ? `<table class="finder-table"><thead><tr><th class="finder-col-size" style="width:70px">结果</th><th>目标</th><th style="width:220px">说明</th></tr></thead><tbody>${details.map((d) => `
        <tr>
          <td class="finder-col-size"><span class="finder-name-text" style="opacity:.8">${esc(statusLabel[d.status] || d.status || '—')}</span></td>
          <td><span class="finder-path-text" data-tip="${esc(d.target || '')}">${esc(d.target || '—')}</span></td>
          <td><span class="finder-name-text" style="opacity:.8">${esc(d.message || '')}</span></td>
        </tr>`).join('')}</tbody></table>` : '<div class="finder-empty">该批次没有明细记录。</div>'}
      <div style="margin-top:10px"><button class="btn btn-secondary btn-small" data-report-back type="button">← 返回报告列表</button></div>`;
    body.querySelector('[data-report-back]').addEventListener('click', () => renderReportList(ctrl));
  }

  function openReportManager() {
    closeReportModal();
    const ctrl = window.modal.create({
      id: 'unReportBackdrop',
      title: '残留清理报告',
      bodyHtml: '<div class="finder-empty">正在读取报告列表…</div>',
      footerClass: 'pw-footer',
      footerHtml: '<button class="btn btn-secondary" data-role="doneBtn" type="button">关闭</button>'
    });
    ctrl.footer.querySelector('[data-role="doneBtn"]').addEventListener('click', closeReportModal);
    renderReportList(ctrl);
  }

  // ==================== 初始化 ====================
  // A3（M3）残留规则库在线更新：刻意做成显式动作、不做定时自动更新——规则库决定
  // 「什么会被当成残留」，替换它必须是用户点出来的一次操作（删除本身仍要逐项勾选 +
  // 快照复核 + 注册表先备份，硬闸在后端）。失败必须可见：清理域 v0.2.2 修过
  // 「异步失败被同步 try/catch 静默吞掉」那一类缺陷，这里不重犯。
  let rulesUpdating = false;

  async function updateResidueRules() {
    if (rulesUpdating) return;
    const btn = document.getElementById('btnResidueRulesUpdate');
    rulesUpdating = true;
    if (btn) btn.disabled = true;
    try {
      const chk = await window.api.uninstall.checkResidueVersion();
      if (!chk || !chk.success) throw new Error((chk && chk.message) || '检查版本失败');
      const cur = chk.data.currentVersion;
      if (!chk.data.newerAvailable) {
        window.app?.toast?.('info', `残留规则库已是最新（版本 ${esc(String(cur))}）`);
        return;
      }
      const up = await window.api.uninstall.updateResidueRules();
      if (!up || !up.success) throw new Error((up && up.message) || '更新失败');
      window.app?.toast?.(
        'success',
        `残留规则库已更新：${esc(String(cur))} → ${esc(String(up.data.rulesVersion))}，重新扫描后生效`
      );
      // 面板已展开时立刻按新规则重扫，免得用户以为「更新了但还是那几条」
      if (currentAppId) await scanAllResidue();
    } catch (e) {
      window.app?.toast?.('error', '残留规则库更新失败: ' + (e && e.message ? e.message : String(e)));
    } finally {
      rulesUpdating = false;
      if (btn) btn.disabled = false;
    }
  }

  function init() {
    if (inited) return;
    inited = true;
    document.querySelectorAll('[data-un-scope]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.dataset.unScope === currentScope) return;
        currentScope = btn.dataset.unScope;
        document.querySelectorAll('[data-un-scope]').forEach((b) => {
          b.classList.toggle('active', b.dataset.unScope === currentScope);
          b.setAttribute('aria-selected', b.dataset.unScope === currentScope ? 'true' : 'false');
        });
        // 切换范围时收起残留面板（上一范围的扫描结果对另一范围无意义）
        const panel = document.getElementById('residuePanel');
        if (panel) panel.style.display = 'none';
        loadApps();
      });
    });
    document.getElementById('uninstallBtnRefresh')?.addEventListener('click', loadApps);
    document.getElementById('btnUninstallReports')?.addEventListener('click', openReportManager);
    document.getElementById('btnResidueRulesUpdate')?.addEventListener('click', updateResidueRules);
    document.getElementById('uninstallList')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-un-app]');
      if (btn && !btn.disabled) runUninstall(btn.dataset.unApp);
      const mod = e.target.closest('[data-un-modify]');
      if (mod && !mod.disabled) runModify(mod.dataset.unModify, 'modify');
      const rep = e.target.closest('[data-un-repair]');
      if (rep && !rep.disabled) runModify(rep.dataset.unRepair, 'repair');
    });
    // 一个入口跑三条链：面板里的「重新扫描」与页头按钮走同一条路
    document.getElementById('residueBtnRescan')?.addEventListener('click', scanAllResidue);
    document.getElementById('btnResidueScanAll')?.addEventListener('click', scanAllResidue);
    document.getElementById('residueBtnClean')?.addEventListener('click', cleanResidue);
    document.getElementById('residueBtnPending')?.addEventListener('click', addPendingDeletes);
    document.getElementById('residueBtnPendingRevoke')?.addEventListener('click', revokePendingDeletes);
    // HiBit §H1：删前是否先打还原包。**默认关**（2026-09-29 裁定不做默认备份）——
    // 整目录动辄几百 MB，静默打包既慢又占盘；勾了才备，且勾了建包失败就整批不删（后端钉）
    const bk = document.getElementById('residueBackupToggle');
    if (bk) {
      bk.checked = readBackupPref();
      bk.addEventListener('change', () => {
        try { localStorage.setItem(BACKUP_PREF_KEY, bk.checked ? '1' : '0'); } catch (e) { /* 偏好写不进不影响本次判断 */ }
        window.app?.toast?.('info', bk.checked
          ? '已开启：删除前会把选中项的内容打进本机还原包，之后可在「备份」列表整批还原'
          : '已关闭：文件只进回收站，不再生成内容还原包');
      });
    }
    document.getElementById('residueList')?.addEventListener('click', onResidueClick);
    loadApps();
  }

  window.uninstall = { init };

  // 进页动态注入时 readyState 已是 complete/interactive，直接初始化（check-idle-scripts 口径）
  if (document.readyState !== 'loading') { init(); }
  else document.addEventListener('DOMContentLoaded', init);
})();
