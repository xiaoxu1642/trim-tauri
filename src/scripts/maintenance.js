// maintenance.js - 系统维护修复组（P2-16）
// 11 项修复任务：分类计数标签 + 任务卡片 + 每项独立确认 + 实时输出面板。
// 批量操作：复选框勾选 + 「执行选中」/「全部执行」+ 进度与成功/失败反馈 + 取消。
// 数据源为主进程 maintenance:tasks（PowerShell 脚本模块），渲染层不硬编码任务逻辑。
(function () {
  'use strict';

  let tasks = [];               // [{ id, title, desc, category, admin }]
  let categories = [];          // ['系统修复','搜索与界面','网络连接']
  let activeCat = '全部';
  let running = null;           // 正在执行的 taskId（同一时刻仅一个）
  const status = new Map();     // taskId -> 'idle'|'running'|'ok'|'warn'|'error'
  const selected = new Set();   // 批量勾选的 taskId（跨分类保留）
  let batch = null;             // 批量状态 { total, done, ok, fail, cancelRequested } | null
  let outputBound = false;

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  const STATUS_LABEL = {
    idle: '执行', running: '执行中…', ok: '已完成', warn: '部分完成', error: '失败'
  };

  // ==================== 维护项详解弹窗内容（v3.2.0） ====================
  // 每项三段：是什么 / 什么情况下会用到它 / 用了之后应该达到的效果。
  // 以任务 id 为键（数据源见 src/scripts-powershell/maintenance-scripts.js）；新增任务时此处需同步补文案，
  // 未收录的 id 弹窗自动回落为 desc 单段展示，不会开天窗。
  const MAINT_INFO = {
    sfc: {
      what: '运行 Windows 系统文件检查器（sfc /scannow），扫描全部受保护的系统文件，并用本地组件存储中的正确版本替换被篡改或损坏的文件。',
      when: '系统出现蓝屏、资源管理器崩溃、系统功能报错、DLL 缺失等疑似系统文件损坏的情况。',
      effect: '受损的系统文件被恢复为微软原始版本，系统稳定性提升。耗时数分钟，结束后会给出「未发现违和 / 已修复 / 无法修复」的明确结论。'
    },
    dism: {
      what: '运行 DISM /RestoreHealth，检查并修复 Windows 组件存储（WinSxS）——它是「系统文件修复 (SFC)」的零件库。',
      when: 'SFC 报告「无法修复」或修复后问题依旧时，先用 DISM 把零件库修好，再跑一遍 SFC 效果最佳。',
      effect: '组件存储恢复一致，SFC 的修复能力随之恢复。耗时更长（可能 10 分钟以上），期间可能联网下载健康修复源。'
    },
    wu: {
      what: '停止更新相关服务，重命名 SoftwareDistribution 与 catroot2 缓存目录后重启服务，相当于给 Windows 更新「恢复出厂设置」。',
      when: '更新长期卡在某个百分比、报错 0x8007xxxx、补丁反复下载失败。',
      effect: '更新缓存与任务队列清空，下次检查更新将重新拉取；已安装的更新不会被卸载，数据不受影响。'
    },
    print: {
      what: '停止 Print Spooler 打印后台服务，清空卡死的打印任务队列文件，再重启服务。',
      when: '打印任务卡在队列里删不掉、打印机显示「正在打印」却毫无动静。',
      effect: '打印队列归零，打印机恢复可响应状态；需要重新下发刚才没打出来的任务。'
    },
    store: {
      what: '运行系统自带的 wsreset.exe，清空 Microsoft Store 应用缓存并自动重启商店。',
      when: '商店打不开、页面一直转圈、应用下载或更新反复报错。',
      effect: '商店缓存清空（登录状态保留），多数「商店打不开 / 下载失败」问题得到修复；完成后商店会自动打开，可手动关闭。'
    },
    audio: {
      what: '重启 Windows Audio 与 AudioEndpointBuilder 两个音频核心服务。',
      when: '突然没声音、耳机/音箱识别异常、任务栏声音图标打叉。',
      effect: '音频服务栈重新初始化，多数「无声」问题即时恢复；音量大小等个人设置不受影响。'
    },
    perfcounters: {
      what: '运行 lodctr /r，从系统备份清单重新注册性能计数器库。',
      when: '任务管理器性能页数值空白、性能监视器报「无法收集计数器数据」。',
      effect: '性能计数器恢复可用，任务管理器/性能监视器重新正常显示 CPU、磁盘、网络等实时数据。'
    },
    iconthumb: {
      what: '删除图标缓存与缩略图缓存数据库，并自动重启资源管理器，让系统重新生成缓存。',
      when: '桌面/任务栏图标变成白块、文件夹缩略图显示错乱或长期不刷新。',
      effect: '缓存重建后图标与缩略图恢复正常显示；重建期间桌面会短暂闪烁，文件本身不受任何影响。'
    },
    search: {
      what: '停止 Windows Search 服务，清空旧索引数据库后重启服务，索引将在后台自动重建。',
      when: '开始菜单/文件搜索无结果、搜出早已删除的旧文件、索引长期卡在「正在编制索引」。',
      effect: '搜索索引从零重建（耗时取决于文件数量），搜索结果恢复准确与实时。'
    },
    dns: {
      what: '执行 ipconfig /flushdns，清空本机 DNS 解析缓存。',
      when: '网站换了服务器但你仍打不开、总是访问到旧页面、解析到了错误地址。',
      effect: '本地解析缓存立即清空，下次访问会重新向 DNS 服务器查询并拿到最新地址，秒级完成、零风险。'
    },
    netstack: {
      what: '重置 Winsock 目录与 TCP/IP 协议栈参数并刷新 DNS，把网络底层配置恢复到系统默认状态。',
      when: '网络异常的「大招」：能连 Wi-Fi 却上不了网、代理/加速器残留劫持、各类疑难断网。',
      effect: '被软件篡改的 LSP 与协议参数归零，网络栈恢复干净状态；需重启电脑完全生效，并重新输入 Wi-Fi 密码连接。'
    },
    net_response: {
      what: '关闭 Windows 多媒体播放时的网络节流（NetworkThrottlingIndex 拉满），并把系统响应性设为 0。',
      when: '后台看视频/听音乐时网速被系统压低、游戏延迟因节流策略升高。',
      effect: '系统不再在播放场景主动限制网络吞吐，网络反馈更快；普通浏览感知有限，游戏、直播、下载场景更明显。'
    },
    tf_net_tcp: {
      what: '通过 netsh 与注册表批量调整 TCP 全局参数：关闭自动调优/ECN/时间戳，启用 RSS、CTCP 拥塞算法等。',
      when: '追求极限低延迟的游戏、竞技或下载场景，愿意用少量兼容性换取网络性能。',
      effect: 'TCP 连接的延迟与吞吐参数得到优化；个别老旧网络设备或 VPN 可能不兼容，出现异常可通过还原点回退。'
    },
    tf_net_tcpip: {
      what: '写入 Tcpip 服务注册表参数：TTL=64、关闭 SACK 与 Nagle 算法、MaxUserPort 拉满、TIME_WAIT 缩短到 30 秒等。',
      when: '高并发连接场景（大量下载任务、本地服务）出现端口耗尽、连接建立偏慢。',
      effect: '连接复用更激进、握手更干脆；家用日常感知不大，所有改动均为可逆的注册表参数。'
    },
    tf_net_lanman: {
      what: '调整 SMB 服务器（LanmanServer 文件共享服务）的会话参数：空闲会话永不断开、关闭 Oplocks 等。',
      when: '局域网共享或 NAS 传输频繁断连、小文件传输速度明显偏慢。',
      effect: '共享会话更稳定，减少频繁断开重连；关闭 Oplocks 后个别场景的共享文件一致性保障会降低。'
    },
    tf_net_nic: {
      what: '遍历所有网卡，把高级属性统一切到「低延迟」档：关闭节能、绿色以太网、WoL、中断调节与流控，RSS 双队列、缓冲区拉大。',
      when: '网游、竞技等对网络延迟抖动极度敏感的场景，可以接受功耗略微增加。',
      effect: '网卡对数据包「即来即走」，延迟与抖动明显变小；笔记本的功耗与发热会略有增加。'
    },
    tf_net_weakhost: {
      what: '对所有网卡（含隐藏网卡）启用 WeakHost 发送/接收模型，替代默认的强主机模型。',
      when: '多网卡（以太网 + Wi-Fi + 虚拟网卡）环境下出现路由异常、部分网段不通。',
      effect: '多网卡间的路由收发更灵活，跨网段访问更顺；网络隔离安全性轻微降低，单网卡环境收益有限。'
    },
    net_qos_scheduler: {
      what: '将组策略 NonBestEffortLimit 设为 0，取消 Windows 默认预留的 QoS 保留带宽（PSched 策略）。',
      when: '大流量下载、直播推流时感觉带宽总被系统「吃掉」一截。',
      effect: '应用可用的带宽上限不再被系统预留削减；企业、校园、VPN 或域策略环境可能被上层配置覆盖。'
    },
    net_disable_netbios: {
      what: '把所有网卡接口的 NetBIOS over TCP/IP 关闭（NetbiosOptions=2）。',
      when: '内网没有老式共享需求、确认没有老设备依赖 NetBIOS，想消除它的广播与安全暴露面。',
      effect: '名称解析改走纯 DNS，内网广播与 NetBIOS 攻击面减少；LAN 游戏、老式 NAS/共享可能依赖它，关闭前请确认。'
    },
    net_disable_lmhosts: {
      what: '关闭 LMHOSTS 文件名称查找（EnableLMHOSTS=0）。',
      when: '没有使用 LMHOSTS 静态解析文件的老式需求，想清理历史遗留的名称解析链路。',
      effect: '名称解析链路更干净、更少干扰；依赖 LMHOSTS 文件的老系统共享会受影响。'
    }
  };

  // 维护项详解弹窗：统一弹窗工厂（modal.js）生成三段式内容，
  // 底部「AI大模型解释」走 maintenance scope 的联网解释，「开始本项修复」复用既有确认+执行链路。
  function openMaintDetail(task) {
    if (!window.modal || typeof window.modal.create !== 'function') {
      window.app?.toast?.('warning', '弹窗组件未就绪，请稍后重试');
      return;
    }
    const info = MAINT_INFO[task.id] || null;
    const section = (title, text) => `
      <div class="maint-detail-block">
        <div class="maint-detail-title">${escapeHtml(title)}</div>
        <div class="maint-detail-text">${escapeHtml(text)}</div>
      </div>`;
    const bodyHtml = `
      <div class="maint-detail-head">
        <span class="maint-detail-cat">${escapeHtml(task.category || '系统维护')}</span>
        ${task.admin ? '<span class="maint-admin-tag" data-tip="需要管理员权限">管理员</span>' : ''}
      </div>
      ${info ? section('是什么', info.what) + section('什么情况下会用到它', info.when) + section('用了之后应该达到的效果', info.effect)
             : section('是什么', task.desc || '暂无说明')}
      <div class="maint-detail-ai" data-role="aiBox">
        <div class="maint-detail-ai-hint">点击「AI大模型解释」后，由所选大模型联网补充解释（需在「设置 → 大模型管理」启用模型）</div>
      </div>`;
    const footerHtml = `
      <button class="btn btn-secondary" data-role="aiBtn" type="button">AI大模型解释</button>
      <span class="model-picker-spacer"></span>
      <button class="btn btn-primary" data-role="runBtn" type="button">开始本项修复</button>`;
    const ctrl = window.modal.create({
      id: 'maintDetailModal-' + task.id,
      title: task.title,
      bodyHtml,
      footerHtml,
      bodyClass: 'maint-detail-body'
    });
    const aiBox = ctrl.body.querySelector('[data-role="aiBox"]');
    const aiBtn = ctrl.footer.querySelector('[data-role="aiBtn"]');
    aiBtn.addEventListener('click', async () => {
      if (!window.api?.aidesc) {
        aiBox.innerHTML = '<div class="intro-ai-fail">当前环境不支持联网 AI 解释</div>';
        return;
      }
      aiBtn.disabled = true;
      aiBtn.textContent = '解释生成中…';
      aiBox.innerHTML = '<div class="intro-ai-skeleton"><span></span><span></span></div>';
      try {
        // scope=maintenance：主进程按系统维护专属提示词生成，缓存按任务标题隔离
        const resp = await window.api.aidesc.get(task.title, task.category || '系统维护', false, 'maintenance');
        if (resp && resp.success && resp.data && resp.data.desc) {
          aiBox.innerHTML = `
            <div class="intro-ai-text">${escapeHtml(resp.data.desc)}</div>
            <div class="intro-ai-meta">来源：${escapeHtml(resp.data.source || 'AI 大模型')}${resp.data.cached ? ' · 缓存' : ''}</div>`;
        } else if (resp && resp.message === 'disabled') {
          aiBox.innerHTML = '<div class="intro-ai-fail">所选大模型尚未启用，请到「设置 → 功能入口 → 大模型管理」启用后重试。</div>';
        } else {
          aiBox.innerHTML = `<div class="intro-ai-fail">${escapeHtml((resp && resp.message) || '暂时无法获取解释，请稍后重试')}</div>`;
        }
      } catch (e) {
        aiBox.innerHTML = `<div class="intro-ai-fail">获取失败：${escapeHtml(e.message)}</div>`;
      } finally {
        aiBtn.disabled = false;
        aiBtn.textContent = 'AI大模型解释';
      }
    });
    ctrl.footer.querySelector('[data-role="runBtn"]').addEventListener('click', () => {
      ctrl.close();
      runTask(task.id);
    });
  }

  function visibleTasks() {
    if (activeCat === '全部') return tasks;
    return tasks.filter(t => t.category === activeCat);
  }

  function countFor(cat) {
    if (cat === '全部') return tasks.length;
    return tasks.filter(t => t.category === cat).length;
  }

  // ==================== 分类计数标签 ====================
  function renderTabs() {
    const el = document.getElementById('maintTabs');
    if (!el) return;
    const cats = ['全部', ...categories];
    el.innerHTML = cats.map(c => {
      const active = c === activeCat ? ' active' : '';
      return `<button class="filter-tab${active}" data-cat="${escapeHtml(c)}">${escapeHtml(c)}<span class="maint-tab-count">${countFor(c)}</span></button>`;
    }).join('');
    el.querySelectorAll('.filter-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        activeCat = btn.dataset.cat;
        renderTabs();
        renderList();
        updateBatchbar();
      });
    });
  }

  // ==================== 任务卡片列表 ====================
  function renderList() {
    const el = document.getElementById('maintList');
    if (!el) return;
    const list = visibleTasks();
    if (!list.length) {
      el.innerHTML = window.emptyState
        ? window.emptyState({ icon: 'search', title: '暂无维护任务', desc: '加载任务清单中，请稍后重试' })
        : '<div class="xtable-empty">暂无任务</div>';
      return;
    }
    const busy = !!running || !!batch;
    el.innerHTML = list.map(t => {
      const st = status.get(t.id) || 'idle';
      const isRunning = running === t.id;
      const isSelected = selected.has(t.id);
      const badge = st !== 'idle' ? `<span class="maint-status maint-status-${st}">${STATUS_LABEL[st] || st}</span>` : '';
      const adminTag = t.admin ? '<span class="maint-admin-tag" data-tip="需要管理员权限">管理员</span>' : '';
      return `
        <div class="maint-card${isSelected ? ' selected' : ''}${isRunning ? ' running' : ''}" data-id="${escapeHtml(t.id)}">
          <label class="maint-check" data-tip="勾选后可批量执行">
            <input type="checkbox" data-check="${escapeHtml(t.id)}" ${isSelected ? 'checked' : ''} ${busy ? 'disabled' : ''} />
          </label>
          <div class="maint-card-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
          </div>
          <div class="maint-card-body">
            <div class="maint-card-title">${escapeHtml(t.title)}${adminTag}${badge}</div>
            <div class="maint-card-desc">${escapeHtml(t.desc)}</div>
          </div>
          <div class="maint-card-actions">
            <button class="btn btn-primary btn-small maint-run-btn" data-run="${escapeHtml(t.id)}" ${busy ? 'disabled' : ''}>
              ${isRunning ? '执行中…' : (st === 'ok' || st === 'warn' || st === 'error' ? '再次执行' : '执行')}
            </button>
          </div>
        </div>`;
    }).join('');
    el.querySelectorAll('[data-run]').forEach(btn => {
      btn.addEventListener('click', () => runTask(btn.dataset.run));
    });
    el.querySelectorAll('[data-check]').forEach(cb => {
      cb.addEventListener('change', () => {
        if (cb.checked) selected.add(cb.dataset.check);
        else selected.delete(cb.dataset.check);
        const card = cb.closest('.maint-card');
        if (card) card.classList.toggle('selected', cb.checked);
        updateBatchbar();
      });
    });
    // v3.2.0：点击卡片主体（非按钮/复选框）→ 弹出本项详解弹窗（是什么/何时用/预期效果 + AI 解释 + 开始修复）
    el.querySelectorAll('.maint-card').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('button, input, label')) return;
        const task = tasks.find(t => t.id === card.dataset.id);
        if (task) openMaintDetail(task);
      });
    });
  }

  // ==================== 批量操作栏 ====================
  function updateBatchbar() {
    const selAll = document.getElementById('maintSelAll');
    const count = document.getElementById('maintSelCount');
    const btnSel = document.getElementById('btnMaintRunSelected');
    const btnAll = document.getElementById('btnMaintRunAll');
    const btnCancel = document.getElementById('btnMaintCancelBatch');
    const progress = document.getElementById('maintBatchProgress');
    if (!selAll || !count || !btnSel || !btnAll || !btnCancel || !progress) return;

    const visible = visibleTasks();
    const selVisible = visible.filter(t => selected.has(t.id)).length;
    const busy = !!batch || !!running;

    // 全选框：全选 / 部分选（indeterminate）/ 未选
    selAll.checked = visible.length > 0 && selVisible === visible.length;
    selAll.indeterminate = selVisible > 0 && selVisible < visible.length;
    selAll.disabled = busy;

    count.textContent = `已选 ${selected.size} 项`;
    btnSel.disabled = busy || selVisible === 0;
    btnSel.textContent = batch ? '批量执行中…' : `执行选中（${selVisible}）`;
    btnAll.disabled = busy || visible.length === 0;
    btnCancel.style.display = batch ? '' : 'none';
    btnCancel.disabled = !batch || batch.cancelRequested;
    btnCancel.textContent = batch && batch.cancelRequested ? '取消中…' : '取消批量';

    if (batch) {
      progress.style.display = 'flex';
      const pct = Math.round((batch.done / batch.total) * 100);
      document.getElementById('maintBatchProgressFill').style.width = pct + '%';
      document.getElementById('maintBatchProgressText').textContent =
        `${batch.done}/${batch.total} · 成功 ${batch.ok} · 失败 ${batch.fail}${batch.cancelRequested ? ' · 取消中' : ''}`;
    } else {
      progress.style.display = 'none';
    }
  }

  // ==================== 输出面板 ====================
  function showOutput(title) {
    const panel = document.getElementById('maintOutput');
    const body = document.getElementById('maintOutputBody');
    const head = document.getElementById('maintOutputTitle');
    if (head) head.textContent = title;
    if (body) body.textContent = '';
    if (panel) panel.style.display = 'block';
  }

  function appendOutput(line) {
    const body = document.getElementById('maintOutputBody');
    if (!body) return;
    body.textContent += (body.textContent ? '\n' : '') + line;
    body.scrollTop = body.scrollHeight;
  }

  function hideOutput() {
    const panel = document.getElementById('maintOutput');
    if (panel && !batch) panel.style.display = 'none';
  }

  // ==================== 执行单个任务（独立确认） ====================
  async function runOne(task) {
    status.set(task.id, 'running');
    renderList();
    try {
      const resp = await window.api.maintenance.run(task.id);
      // 复核 N1（提权半闭环，2026-09-16）：admin 任务未提权时服务端回传 needAdmin，
      // 此前只输出一条错误文本、无提权入口；现在弹出提权确认（对齐 runtimes 范式）
      if (resp && resp.needAdmin) {
        status.set(task.id, 'error');
        const elevated = await window.app?.requestElevation?.('该维护任务需要管理员权限才能执行系统级操作。');
        appendOutput(elevated
          ? '已获得管理员权限，应用将以管理员身份重启，重启后请重新执行本任务'
          : '未提权，任务已取消（需要管理员权限）');
        return 'error';
      }
      const result = resp?.data?.result || (resp?.success ? 'ok' : 'error');
      status.set(task.id, resp?.success ? (result === 'ok' ? 'ok' : result === 'warn' ? 'warn' : 'error') : 'error');
      if (!resp?.success) appendOutput('错误：' + (resp?.message || '执行失败'));
      return status.get(task.id);
    } catch (e) {
      status.set(task.id, 'error');
      appendOutput('异常：' + e.message);
      return 'error';
    } finally {
      renderList();
    }
  }

  async function runTask(taskId) {
    if (running || batch) { window.app?.toast?.('warning', '已有维护任务在执行，请稍候'); return; }
    const task = tasks.find(t => t.id === taskId);
    if (!task) return;
    if (!window.api?.maintenance) { window.app?.toast?.('warning', '浏览器预览模式不支持执行维护任务'); return; }

    // 独立确认：说明该任务会做什么、是否可逆、是否需重启
    const ok = await window.app?.confirm?.(
      `执行「${task.title}」`,
      `${task.desc}\n\n该操作将立即开始，期间请勿关闭应用。${task.admin ? '\n（需要管理员权限）' : ''}`,
      '确认执行',
      '取消'
    );
    if (!ok) return;

    running = taskId;
    updateBatchbar();
    showOutput(`${task.title} · 执行输出`);

    try {
      const st = await runOne(task);
      window.app?.toast?.(st === 'ok' ? 'success' : (st === 'warn' ? 'warning' : 'error'),
        `${task.title} ${STATUS_LABEL[st] || '完成'}`);
    } finally {
      running = null;
      renderList();
      updateBatchbar();
    }
  }

  // ==================== 批量执行（顺序逐项 + 可取消） ====================
  async function runBatch(mode) {
    if (running || batch) { window.app?.toast?.('warning', '已有维护任务在执行，请稍候'); return; }
    if (!window.api?.maintenance) { window.app?.toast?.('warning', '浏览器预览模式不支持执行维护任务'); return; }
    const list = mode === 'all' ? visibleTasks() : visibleTasks().filter(t => selected.has(t.id));
    if (!list.length) {
      window.app?.toast?.('warning', mode === 'all' ? '当前分类下暂无任务' : '请先勾选要执行的项目');
      return;
    }

    const adminCount = list.filter(t => t.admin).length;
    const ok = await window.app?.confirm?.(
      `批量执行 ${list.length} 项维护任务`,
      `将按顺序逐项执行${mode === 'all' ? '当前分类下的全部项目' : '已勾选的项目'}，执行期间可随时点「取消批量」停止后续项目（正在执行的一项会完成后停止）。\n` +
      `${adminCount ? `\n其中 ${adminCount} 项需要管理员权限。` : ''}\n开始后请勿关闭应用。`,
      '开始批量执行',
      '取消'
    );
    if (!ok) return;

    batch = { total: list.length, done: 0, ok: 0, fail: 0, cancelRequested: false };
    showOutput(`批量执行 ${list.length} 项 · 输出`);
    appendOutput(`===== 批量执行开始：共 ${list.length} 项 =====`);
    updateBatchbar();
    renderList();

    for (const task of list) {
      if (batch.cancelRequested) {
        appendOutput(`—— 已取消：跳过「${task.title}」及后续项目 ——`);
        break;
      }
      running = task.id;
      appendOutput(`—— [${batch.done + 1}/${batch.total}] ${task.title} ——`);
      updateBatchbar();

      const st = await runOne(task);
      if (st === 'ok' || st === 'warn') batch.ok++; else batch.fail++;
      batch.done++;
      running = null;
      updateBatchbar();
    }

    const cancelled = batch.cancelRequested;
    const summary = `成功 ${batch.ok} 项 · 失败 ${batch.fail} 项${cancelled ? ' · 已取消剩余' : ''}`;
    appendOutput(`===== 批量执行结束：${summary} =====`);
    window.app?.toast?.(
      cancelled ? 'warning' : (batch.fail ? 'warning' : 'success'),
      cancelled ? `批量执行已取消（${summary}）` : (batch.fail ? `批量执行完成：${summary}` : `批量执行全部完成：${summary}`),
      1000
    );
    batch = null;
    updateBatchbar();
    renderList();
  }

  function cancelBatch() {
    if (!batch || batch.cancelRequested) return;
    batch.cancelRequested = true;
    appendOutput('—— 收到取消请求：当前任务完成后停止 ——');
    window.app?.toast?.('info', '将在当前任务完成后停止批量执行');
    updateBatchbar();
  }

  function toggleSelectAll(checked) {
    visibleTasks().forEach(t => {
      if (checked) selected.add(t.id); else selected.delete(t.id);
    });
    renderList();
    updateBatchbar();
  }

  // 实时输出：仅接收当前运行任务的行
  function onOutput(data) {
    if (!data || data.taskId !== running) return;
    appendOutput(data.line);
  }

  async function loadTasks() {
    if (!window.api?.maintenance) { renderList(); return; }
    try {
      const resp = await window.api.maintenance.tasks();
      if (resp && resp.success && Array.isArray(resp.data)) {
        tasks = resp.data;
        categories = Array.isArray(resp.categories) ? resp.categories : [];
        renderTabs();
        renderList();
        updateBatchbar();
      }
    } catch (e) {
      // 静默：保留空态
    }
  }

  function init() {
    if (!outputBound) {
      outputBound = true;
      document.getElementById('btnMaintOutputClose')?.addEventListener('click', hideOutput);
      document.getElementById('maintSelAll')?.addEventListener('change', (e) => toggleSelectAll(e.target.checked));
      document.getElementById('btnMaintRunSelected')?.addEventListener('click', () => runBatch('selected'));
      document.getElementById('btnMaintRunAll')?.addEventListener('click', () => runBatch('all'));
      document.getElementById('btnMaintCancelBatch')?.addEventListener('click', cancelBatch);
      if (window.api?.maintenance?.onOutput) {
        window.api.maintenance.onOutput(onOutput);
      }
    }
    renderTabs();
    renderList();
    updateBatchbar();
    loadTasks();
  }

  window.maintenance = { init };
})();
