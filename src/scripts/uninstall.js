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
  let currentAppId = '';
  // 三条链（规则库 / 失效登记 / 卸载记录）共用一个面板与一份快照，分组结果留在这里渲染
  // 无选中程序时的合成 id：残留不属于任何单个程序，批次报告按它归档（执行侧只用于落报告）
  const MACHINE_APP_ID = 'MACHINE|all';

  // 删前备份偏好（HiBit §H1 还原包）。取「显式关过才算关」以外的最保守解：
  // 读不到 / 读失败一律按关，因为开备份会带来几百 MB 落盘，猜错方向的代价不对称。
  function esc(s) { return window.ds.esc(s); }
  function fmtSizeKb(kb) {
    kb = Number(kb) || 0;
    if (kb <= 0) return '—';
    const units = ['KB', 'MB', 'GB'];
    let v = kb, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
  }

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
        <td class="finder-col-size" style="width:290px">
          <button class="btn btn-secondary btn-small" data-un-app="${esc(a.id)}"${noRemoveAttr(a)}>卸载</button>
          <button class="btn btn-secondary btn-small" data-un-modify="${esc(a.id)}"${modifyBtnAttr(a)}${noModifyAttr(a)}>修改</button>
          <button class="btn btn-secondary btn-small" data-un-repair="${esc(a.id)}"${modifyBtnAttr(a)}${noRepairAttr(a)}>修复</button>
        </td>
      </tr>`).join('');
    return `
      <table class="finder-table">
        <thead><tr><th>程序<span class="page-summary">共 ${apps.length} 个应用</span></th><th class="finder-col-size" style="width:180px">发行商</th><th class="finder-col-size" style="width:110px">版本</th><th class="finder-col-size" style="width:90px">大小</th><th class="finder-col-size" style="width:110px">安装日期</th><th class="finder-col-size" style="width:290px">操作</th></tr></thead>
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
          <td class="finder-col-size" style="width:230px">
            <button class="btn btn-secondary btn-small" data-un-app="${esc(a.id)}"${uninstallBlockAttr(a)}>卸载</button>
          </td>
        </tr>`).join('');
      return `<div class="finder-group-header"><span>${title} · ${list.length} 项</span></div>
        <table class="finder-table">
          <thead><tr><th>应用名${withTotal ? `<span class="page-summary">共 ${apps.length} 个应用</span>` : ''}</th><th class="finder-col-size" style="width:190px">发布者</th><th class="finder-col-size" style="width:130px">版本</th><th class="finder-col-size" style="width:230px">操作</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`;
    };
    // 总数只落在第一张表的表头：两组都在时归「第三方应用」，第三方为空时归「Windows 应用」
    return section('第三方应用', third, true) + section('Windows 应用', sys, !third.length);
  }

  // ==================== 卸载 ====================
  // §2.3（2026-10-06 拍板）：卸载前可选创建系统还原点。默认关；失败只提示、不拦卸载
  // —— 还原点是保护，不是前置条件（对齐 HiBit 语义）。复用 optimizer 域现有命令，
  // Rust 侧零改动：check_restore 是 readonly 档、create_restore 是 MAIN 档，主窗都能调。
  const RESTORE_PREF_KEY = 'trim.uninstall.restorePoint';
  // D2（v4 审查）：读失败/坏值走「未开启」方向 + 留痕（同残留副窗备份开关的口径）。
  function readRestorePref() {
    let raw = null;
    try { raw = localStorage.getItem(RESTORE_PREF_KEY); }
    catch (e) {
      window.app?.log?.('warn', `卸载页还原点开关偏好读取失败，已按未开启处理: ${e.message}`);
      return false;
    }
    if (raw === '1') return true;
    if (raw !== null && raw !== '' && raw !== '0') {
      window.app?.log?.('warn', `卸载页还原点开关偏好值异常（${raw}），已按未开启处理`);
    }
    return false;
  }

  async function createRestorePointIfEnabled() {
    const check = window.api?.optimizer?.checkRestore;
    const create = window.api?.optimizer?.createRestore;
    if (!check || !create) return; // 通道缺失按「无此能力」处理，不拦卸载
    // 先查环境：检查链路明确失败多为系统还原未启用——如实提示并跳过，省一次数十秒的无效创建
    startFakeProgress('正在检查系统还原点环境…');
    let probe = null;
    try { probe = await check(); } catch (e) { probe = null; }
    if (probe && probe.success === false) {
      window.app?.toast?.('warning', '系统还原点检查未通过（系统还原可能未启用），将继续卸载');
      finishFakeProgress();
      return;
    }
    // 创建中给独立进度提示：创建还原点耗时可到数十秒，沿用卸载等待的假进度条避免「像卡死」
    startFakeProgress('正在创建系统还原点…可能需要数十秒');
    try {
      const cr = await create();
      if (cr && cr.success) {
        window.app?.toast?.('success', '系统还原点已创建，开始卸载');
      } else {
        window.app?.toast?.('warning', '还原点创建失败，将继续卸载: ' + ((cr && cr.message) || '原因未知'));
      }
    } catch (e) {
      window.app?.toast?.('warning', '还原点创建失败，将继续卸载: ' + (e.message || e));
    } finally {
      finishFakeProgress();
    }
  }

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
    // §2.3：确认通过后、卸载器启动前建还原点（开关关时直进卸载，行为与现状一致）
    if (readRestorePref()) {
      await createRestorePointIfEnabled();
    }
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
      } else if (d.exitCode == null) {
        // 审查 M-07 订正：后端硬等待超时（UninstallerWait::TimedOut）时 exitCode 为 null，
        // 而 watch_uninstaller 只要卸载键消失就立刻返回 stillListed=false——**不代表
        // 卸载器退出了**。若继续往下走分支链，这里会落到 usedSilent 的「静默卸载完成」
        // 并照样打开残留窗，把「进程可能还在跑」播报成「已完成」。超时必须最先判，
        // 且只播报后端那句如实结论，不在这里合成「成功/仍在列表中」的结论。
        window.app?.toast?.('warning', d.message || '等待卸载器超时，卸载状态未知（未强制终止）');
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
      // 审查 M-07 订正：超时态**不**自动开残留副窗——卸载器可能还在写盘，
      // 此时扫描到的「残留」是卸载中途的半成品，照着删会和安装器抢文件。
      // 用户等卸载真正结束（或重启后）再手动点扫描即可，入口在残留副窗自己那里。
      if (d.exitCode == null && !isAppx) {
        window.app?.toast?.('info', '请等卸载器自行结束后再扫描残留；也可重启系统后重试');
        return;
      }
      // v0.7.0 用户拍板：卸载完成后弹的就是残留副窗（面板不再留在主窗里）。
      // 主窗只负责把「刚卸载的是哪个」递过去；扫描、勾选、删除全在那扇窗内。
      currentAppId = appId;
      await openResidueWindow(appId);
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

  // ==================== 残留副窗入口（v0.7.0：残留链在这一扇窗里的唯一界面） ====================
  //
  // 只有「卸载完成后自动弹出」这一条来路（runUninstall 尾部调本函数）；主窗工具栏不再提供
  // 常驻入口。开窗失败必须说清 —— 窗口没起来时，最容易读成「这台机器没问题」。
  // appId 只是提示后端扫哪个，取值闸在 Rust 侧（开窗前一次、执行链再一次），这里不自己判形状。
  async function openResidueWindow(appId) {
    try {
      const r = await window.api.residueWindow.openWindow(appId || '');
      if (r && r.success === false) {
        window.app?.toast?.('error', r.message || '打开残留扫描窗口失败');
        return false;
      }
      return true;
    } catch (e) {
      window.app?.toast?.('error', '打开残留扫描窗口失败: ' + ((e && e.message) || e));
      return false;
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
        // v0.7.0：残留面板不在主窗了，切范围只需重载列表；副窗里那一版结果由用户自己重扫
        loadApps();
      });
    });
    document.getElementById('uninstallBtnRefresh')?.addEventListener('click', loadApps);
    document.getElementById('btnUninstallReports')?.addEventListener('click', openReportManager);
    // §2.3：还原点开关的偏好持久化（新式命名对齐 trim.residue.backupPack；读失败按默认关）
    const restoreToggle = document.getElementById('uninstallRestoreToggle');
    if (restoreToggle) {
      restoreToggle.checked = readRestorePref();
      restoreToggle.addEventListener('change', () => {
        try { localStorage.setItem(RESTORE_PREF_KEY, restoreToggle.checked ? '1' : '0'); }
        catch (e) { window.app?.log?.('warn', `卸载页还原点开关偏好写入失败（本次会话有效）: ${e.message}`); }
      });
    }
    document.getElementById('uninstallList')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-un-app]');
      if (btn && !btn.disabled) runUninstall(btn.dataset.unApp);
      const mod = e.target.closest('[data-un-modify]');
      if (mod && !mod.disabled) runModify(mod.dataset.unModify, 'modify');
      const rep = e.target.closest('[data-un-repair]');
      if (rep && !rep.disabled) runModify(rep.dataset.unRepair, 'repair');
      // 行内「查残留」按钮已按用户 2026-10-05 裁定删除：软件既然还装在机器上，谈不上残留。
      // 唯一的入口是卸载完成后自动打开残留副窗（见 runUninstall 尾部），主窗已无常驻入口。
    });
    // v0.7.0：residueBtn* / residueBackupToggle / residueList 这些主窗元素随面板一起搬走了，
    // 对应的监听不在这儿 —— 勾选、删除、删前备份偏好、重启后撤回落 in src/scripts/residue-window.js
    loadApps();
  }

  window.uninstall = { init };

  // 进页动态注入时 readyState 已是 complete/interactive，直接初始化（check-idle-scripts 口径）
  if (document.readyState !== 'loading') { init(); }
  else document.addEventListener('DOMContentLoaded', init);
})();
