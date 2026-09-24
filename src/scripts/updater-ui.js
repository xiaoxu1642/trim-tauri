// src/scripts/updater-ui.js — 自动更新渲染层状态机
// 批次：自动更新接入（2026-09-12）
// 约束：
// 1) 复用 modal.js 统一弹窗骨架（window.modal.create）与 .progress-bar/.progress-fill 现成件；
// 2) 所有动态文本（版本号、更新日志、错误信息）一律 textContent 赋值，禁止拼 HTML；
// 3) window.api / window.modal 缺失时优雅降级（与 ds 未加载兜底一致）；
// 4) 启动后台静默检查的 checking/latest/error 不弹窗，仅手动检查与 available/ready 显性呈现。
(function () {
  'use strict';

  const MODAL_ID = 'updaterModal';
  // v3.6.5 M1-1：签名校验失败时引导用户手动下载的唯一出口。走既有 app:open-external
  // 通道（主进程强制 https-only，见 main.js:1041-1048），故此处不会出现非 https 目标。
  const RELEASES_URL = 'https://github.com/xiaoxu1642/Trim/releases/latest';

  // 主进程推送的状态负载：phase/idle/checking/available/latest/downloading/ready/error
  const state = {
    phase: 'idle',
    percent: 0,
    version: '',
    currentVersion: '',
    releaseNotes: '',
    releaseDate: '',
    message: '',
    speed: 0,
    transferred: 0,
    total: 0
  };

  let ctrl = null;          // window.modal.create 返回的控制器
  let modalKind = '';       // 当前弹窗形态（避免下载进度刷新时重建弹窗）
  let unbind = null;
  let pendingManual = false; // 点击「检查更新」后置真，checking 事件到达时快照
  let activeManual = false;  // 本轮检查是否手动触发（决定 latest/error 是否打扰用户）

  // ---------------- 工具 ----------------
  function $(sel, root) { return (root || document).querySelector(sel); }

  function toast(type, message, duration) {
    try { window.app && window.app.toast(type, message, duration || 3500); } catch (_) {}
  }

  // 字节数/速率格式化（electron-updater 给的是 byte 与 byte/s）
  function fmtBytes(n) {
    const v = Number(n) || 0;
    if (v < 1024) return v + ' B';
    const units = ['KB', 'MB', 'GB'];
    let val = v / 1024;
    let i = 0;
    while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
    return val.toFixed(val >= 100 ? 0 : 1) + ' ' + units[i];
  }

  // ---------------- 更新说明渲染 ----------------
  // 背景（v3.5.1）：releaseNotes 原样 textContent 输出，导致两类内容都不可读——
  //   ① 历史版本把发布说明写成了 HTML（<h2>/<p>/<ul>/<li>），标签被当正文显示；
  //   ② GitHub 惯用的 Markdown（## / - / **）同样不换行不成块。
  // 约束：仍然不拼 HTML 字符串。HTML 分支走 DOMParser（惰性文档，不执行脚本）后
  // 按白名单**重建**节点；Markdown 分支逐行建节点。两条路最终都只产出 createElement/
  // createTextNode，动态文本永远不会成为标记的一部分。

  // 白名单：块级与内联都只放行这些，其余标签只保留其文字内容
  const NOTES_TAGS = new Set([
    'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'P', 'UL', 'OL', 'LI',
    'BLOCKQUOTE', 'PRE', 'CODE', 'HR', 'BR', 'STRONG', 'B', 'EM', 'I', 'A',
    'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD'
  ]);

  function looksLikeHtml(text) {
    return /<\/?(h[1-6]|p|ul|ol|li|div|br|strong|b|em|i|code|pre|blockquote|hr|table|tr|td|th)\b[^>]*>/i.test(text);
  }

  // 把惰性文档里白名单内的节点递归重建成真实节点；未放行的标签被"脱壳"，只留文字
  function appendSanitized(src, dest) {
    const kids = src.childNodes || [];
    for (let i = 0; i < kids.length; i++) {
      const node = kids[i];
      if (node.nodeType === 3) {
        dest.appendChild(document.createTextNode(node.nodeValue));
        continue;
      }
      if (node.nodeType !== 1) continue;
      const tag = node.tagName.toUpperCase();
      if (!NOTES_TAGS.has(tag)) { appendSanitized(node, dest); continue; }
      const el = document.createElement(tag.toLowerCase());
      if (tag === 'A') {
        const href = node.getAttribute('href') || '';
        // 只放行 http(s)，其余（含 javascript:）降级为纯文本链接
        if (/^https?:\/\//i.test(href)) {
          el.setAttribute('href', href);
          el.setAttribute('target', '_blank');
          el.setAttribute('rel', 'noreferrer noopener');
        }
      }
      appendSanitized(node, el);
      dest.appendChild(el);
    }
  }

  // Markdown 行内：**粗** / *斜* / `码` / [文字](链接)，其余一律当文字
  const INLINE_RE = /\*\*([^*]+)\*\*|__([^_]+)__|\*([^*\n]+)\*|`([^`\n]+)`|\[([^\]\n]+)\]\((https?:\/\/[^)\s]+)\)/g;

  function appendInline(text, dest) {
    const src = String(text == null ? '' : text);
    let last = 0;
    let m;
    INLINE_RE.lastIndex = 0;
    while ((m = INLINE_RE.exec(src)) !== null) {
      if (m.index > last) dest.appendChild(document.createTextNode(src.slice(last, m.index)));
      let el = null;
      if (m[1] !== undefined || m[2] !== undefined) el = document.createElement('strong');
      else if (m[3] !== undefined) el = document.createElement('em');
      else if (m[4] !== undefined) el = document.createElement('code');
      else if (m[5] !== undefined) {
        el = document.createElement('a');
        el.setAttribute('href', m[6]);
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noreferrer noopener');
        el.appendChild(document.createTextNode(m[5]));
      }
      if (el && el.tagName !== 'A') el.appendChild(document.createTextNode(m[1] || m[2] || m[3] || m[4]));
      if (el) dest.appendChild(el);
      last = m.index + m[0].length;
    }
    if (last < src.length) dest.appendChild(document.createTextNode(src.slice(last)));
  }

  const MD_HEADING_RE = /^\s{0,3}(#{1,6})\s+(.*)$/;
  const MD_UL_RE = /^\s{0,3}[-*•·]\s+(.*)$/;
  const MD_OL_RE = /^\s{0,3}(\d{1,3})[.、)]\s+(.*)$/;
  const MD_HR_RE = /^\s{0,3}([-*_])\s*(\1\s*){2,}$/;

  // Markdown 子集：标题 / 无序有序列表 / 引用 / 分隔线 / 围栏代码 / 段落
  function renderMarkdownNotes(text) {
    const frag = document.createDocumentFragment();
    const lines = String(text).replace(/\r\n?/g, '\n').split('\n');
    let list = null;        // 当前列表容器（ul / ol）
    let listTag = '';
    let quote = null;
    let para = null;
    let fenced = null;      // 围栏代码块内容

    function closeBlocks() {
      if (list) { frag.appendChild(list); list = null; listTag = ''; }
      if (quote) { frag.appendChild(quote); quote = null; }
      if (para) { frag.appendChild(para); para = null; }
    }
    function openList(tag) {
      if (list && listTag === tag) return;
      if (list) { frag.appendChild(list); list = null; }
      list = document.createElement(tag);
      listTag = tag;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (fenced !== null) {
        if (/^\s{0,3}```/.test(line)) {
          const pre = document.createElement('pre');
          const code = document.createElement('code');
          code.appendChild(document.createTextNode(fenced.join('\n')));
          pre.appendChild(code);
          frag.appendChild(pre);
          fenced = null;
        } else {
          fenced.push(line);
        }
        continue;
      }
      if (/^\s{0,3}```/.test(line)) { closeBlocks(); fenced = []; continue; }
      if (!line.trim()) { closeBlocks(); continue; }

      const hr = MD_HR_RE.exec(line);
      if (hr) { closeBlocks(); frag.appendChild(document.createElement('hr')); continue; }

      const h = MD_HEADING_RE.exec(line);
      if (h) {
        closeBlocks();
        const lv = Math.min(6, h[1].length + 1); // 发布说明的 # 当二级用，避免盖过弹窗标题
        const el = document.createElement('h' + lv);
        appendInline(h[2].trim(), el);
        frag.appendChild(el);
        continue;
      }

      const ul = MD_UL_RE.exec(line);
      if (ul) { if (quote) { quote = null; } openList('ul'); const li = document.createElement('li'); appendInline(ul[1].trim(), li); list.appendChild(li); continue; }
      const ol = MD_OL_RE.exec(line);
      if (ol) { if (quote) { quote = null; } openList('ol'); const li = document.createElement('li'); appendInline(ol[2].trim(), li); list.appendChild(li); continue; }

      if (/^\s{0,3}>\s?/.test(line)) {
        if (list) { frag.appendChild(list); list = null; listTag = ''; }
        if (!quote) { quote = document.createElement('blockquote'); frag.appendChild(quote); }
        const p = document.createElement('p');
        appendInline(line.replace(/^\s{0,3}>\s?/, ''), p);
        quote.appendChild(p);
        continue;
      }

      if (list) { frag.appendChild(list); list = null; listTag = ''; }
      if (quote) { quote = null; }
      if (!para) { para = document.createElement('p'); }
      else { para.appendChild(document.createTextNode(' ')); }
      appendInline(line.trim(), para);
    }
    if (fenced !== null && fenced.length) {
      const pre = document.createElement('pre');
      const code = document.createElement('code');
      code.appendChild(document.createTextNode(fenced.join('\n')));
      pre.appendChild(code);
      frag.appendChild(pre);
    }
    closeBlocks();
    return frag;
  }

  // 统一入口：HTML 体走白名单重建，其余走 Markdown 子集；全空则回退兜底文案
  function renderNotes(container, raw) {
    if (!container) return;
    const text = String(raw == null ? '' : raw).trim();
    container.textContent = '';
    if (!text) {
      container.appendChild(document.createTextNode('本次更新包含问题修复与体验优化。'));
      container.classList.remove('upd-notes-rich');
      return;
    }
    try {
      if (looksLikeHtml(text) && typeof DOMParser === 'function') {
        const doc = new DOMParser().parseFromString(text, 'text/html');
        appendSanitized(doc.body, container);
      } else {
        container.appendChild(renderMarkdownNotes(text));
      }
    } catch (_) {
      container.textContent = '';
      container.appendChild(document.createTextNode(text));
    }
    // 富文本态由 CSS 决定块级排版（纯文本回退时仍保留 pre-wrap 换行）
    const hasBlocks = container.querySelector('h1,h2,h3,h4,h5,h6,p,ul,ol,blockquote,pre,hr,table') !== null;
    if (hasBlocks) container.classList.add('upd-notes-rich');
    else container.classList.remove('upd-notes-rich');
  }

  // ---------------- 弹窗构建（静态骨架，无任何动态文本插值） ----------------
  function bodyHtml(kind) {
    if (kind === 'checking') {
      return '<div class="upd-checking"><span class="upd-spinner" aria-hidden="true"></span>' +
        '<span class="upd-checking-text">正在检查更新…</span></div>';
    }
    if (kind === 'available') {
      const badge = window.ds && window.ds.badgeHtml
        ? window.ds.badgeHtml('accent', '新版本', { small: true })
        : '<span class="ds-badge accent sm">新版本</span>';
      return '<div class="upd-available">' +
        '<div class="upd-version-line">' + badge + '<span class="upd-version-new"></span></div>' +
        '<div class="upd-version-current"></div>' +
        '<div class="upd-notes" tabindex="0"></div>' +
        '</div>';
    }
    if (kind === 'downloading') {
      return '<div class="upd-dl">' +
        '<div class="upd-dl-head"><span class="upd-dl-label">正在下载更新</span>' +
        '<span class="upd-dl-percent">0%</span></div>' +
        '<div class="progress-bar" role="progressbar" aria-label="更新包下载进度" ' +
        'aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">' +
        '<div class="progress-fill upd-dl-fill"></div></div>' +
        '<div class="upd-dl-meta"><span class="upd-dl-size"></span>' +
        '<span class="upd-dl-speed"></span></div>' +
        '</div>';
    }
    if (kind === 'ready') {
      return '<div class="upd-ready">' +
        '<div class="upd-ready-title">更新已下载完成</div>' +
        '<p class="upd-ready-desc"></p></div>';
    }
    if (kind === 'error') {
      // v3.6.5 M1-1：签名类失败时额外展示一段说明（默认隐藏，由 fillModal 按 state.sigFailed 控制）
      return '<div class="upd-error"><div class="upd-error-msg"></div>' +
        '<p class="upd-error-sig" hidden></p></div>';
    }
    return '';
  }

  function footerHtml(kind) {
    const right = '<span class="model-picker-spacer"></span>';
    if (kind === 'checking') {
      return right + '<button class="btn btn-secondary" type="button" data-upd="close">关闭</button>';
    }
    if (kind === 'available') {
      return right +
        '<button class="btn btn-secondary" type="button" data-upd="later">以后再说</button>' +
        '<button class="btn btn-primary" type="button" data-upd="download">下载更新</button>';
    }
    if (kind === 'downloading') {
      return right + '<button class="btn btn-secondary" type="button" data-upd="cancel">取消下载</button>';
    }
    if (kind === 'ready') {
      return right +
        '<button class="btn btn-secondary" type="button" data-upd="later">稍后重启</button>' +
        '<button class="btn btn-primary" type="button" data-upd="install">立即重启</button>';
    }
    if (kind === 'error') {
      // v3.6.5 M1-1：签名类失败时多给一个「前往下载页」出口（默认隐藏）。
      // 为什么必须给：fail-closed 之后用户会「什么都点不动」，没有手动出口的安全策略就等于功能故障。
      return right +
        '<button class="btn btn-secondary" type="button" data-upd="close">关闭</button>' +
        '<button class="btn btn-secondary" type="button" data-upd="releases" hidden>前往下载页</button>' +
        '<button class="btn btn-primary" type="button" data-upd="retry">重试</button>';
    }
    return '';
  }

  function titleOf(kind) {
    return {
      checking: '检查更新',
      available: '发现新版本',
      downloading: '下载更新',
      ready: '更新就绪',
      error: '更新失败'
    }[kind] || '检查更新';
  }

  function closeModal() {
    const c = ctrl;
    ctrl = null;
    modalKind = '';
    try { c && c.close(); } catch (_) {}
  }

  function openModal(kind) {
    if (!window.modal || !window.modal.create) return false;
    if (ctrl && modalKind === kind) { fillModal(kind); return true; }
    closeModal();
    ctrl = window.modal.create({
      id: MODAL_ID,
      title: titleOf(kind),
      // v3.5.1：更新说明要成块排版，原 440px 太窄导致每行只放得下十来个字；
      // 只在 available 态放宽，其余态维持紧凑宽度
      width: kind === 'available' ? 620 : 440,
      bodyHtml: bodyHtml(kind),
      footerHtml: footerHtml(kind),
      onRequestClose: () => {
        // 下载中点关闭/X/Esc 等同显式取消，避免弹窗关了下载仍偷跑
        if (modalKind === 'downloading') {
          try { window.api.updater.cancelDownload(); } catch (_) {}
        }
      },
      onClose: () => { ctrl = null; modalKind = ''; }
    });
    modalKind = kind;
    bindFooter(kind);
    fillModal(kind);
    return true;
  }

  // footer 按钮统一委托（动态文本无关，仅分发动作）
  function bindFooter(kind) {
    if (!ctrl || !ctrl.footer) return;
    ctrl.footer.addEventListener('click', e => {
      const btnEl = e.target.closest('[data-upd]');
      if (!btnEl) return;
      const act = btnEl.getAttribute('data-upd');
      try {
        if (act === 'download') window.api.updater.download();
        else if (act === 'cancel') window.api.updater.cancelDownload();
        else if (act === 'install') window.api.updater.install();
        else if (act === 'retry') manualCheck();
        else if (act === 'releases') {
          // v3.6.5 M1-1：手动下载出口（复用既有 open-external，主进程侧已强制 https）
          try { window.api.openExternal(RELEASES_URL); } catch (_) {}
        }
        else if (act === 'later' || act === 'close') closeModal();
      } catch (err) { /* IPC 异常走 error 状态回流，不在按钮回调里抛 */ }
    });
  }

  // 按形态把 state 里的动态数据写入弹窗（全部 textContent / 样式，无 HTML 拼接）
  function fillModal(kind) {
    if (!ctrl) return;
    const root = ctrl.modal;

    if (kind === 'available') {
      $('.upd-version-new', root).textContent = 'v' + (state.version || '');
      $('.upd-version-current', root).textContent =
        '当前版本 v' + (state.currentVersion || '');
      const notes = $('.upd-notes', root);
      // v3.5.1：releaseNotes 可能是 HTML 体、Markdown 或空；一律经渲染器转成可读版式
      renderNotes(notes, state.releaseNotes);
    } else if (kind === 'downloading') {
      fillDownload();
    } else if (kind === 'ready') {
      $('.upd-ready-desc', root).textContent =
        '新版本 v' + (state.version || '') + ' 已下载并校验完成，重启 Trim 后即可生效。';
    } else if (kind === 'error') {
      $('.upd-error-msg', root).textContent = state.message || '检查更新失败，请稍后重试。';
      // v3.6.5 M1-1：签名类失败额外展示说明并露出手动下载出口
      const sigEl = $('.upd-error-sig', root);
      const relBtn = root.querySelector('[data-upd="releases"]');
      if (sigEl) {
        sigEl.textContent = state.sigFailed
          ? '自动更新已被安全策略阻止：未通过发布签名校验的安装包不会被执行。你可以到官方发布页面手动下载安装包。'
          : '';
        sigEl.hidden = !state.sigFailed;
      }
      if (relBtn) relBtn.hidden = !state.sigFailed;
    }
  }

  function fillDownload() {
    if (!ctrl || modalKind !== 'downloading') return;
    const root = ctrl.modal;
    const pct = Math.max(0, Math.min(100, Number(state.percent) || 0));
    const percentEl = $('.upd-dl-percent', root);
    const fillEl = $('.upd-dl-fill', root);
    const sizeEl = $('.upd-dl-size', root);
    const speedEl = $('.upd-dl-speed', root);
    if (percentEl) percentEl.textContent = pct + '%';
    // 优先走 ds.progress.setFill（钳值 + ARIA），ds 缺席时直写宽度降级
    if (window.ds && window.ds.progress && typeof window.ds.progress.setFill === 'function') {
      window.ds.progress.setFill(fillEl, pct);
    } else if (fillEl) {
      fillEl.style.width = pct + '%';
      const host = fillEl.parentElement;
      if (host) host.setAttribute('aria-valuenow', String(Math.round(pct)));
    }
    if (sizeEl) {
      sizeEl.textContent = state.total
        ? fmtBytes(state.transferred) + ' / ' + fmtBytes(state.total)
        : '';
    }
    if (speedEl) speedEl.textContent = state.speed ? fmtBytes(state.speed) + '/s' : '';
  }

  // ---------------- 设置页行状态 ----------------
  let rowBtn = null;
  let rowHint = null;

  function setRow(text, disabled, hint) {
    if (rowBtn) {
      rowBtn.textContent = text;
      rowBtn.disabled = !!disabled;
    }
    if (rowHint && hint !== undefined) rowHint.textContent = hint;
  }

  function syncRow() {
    const cur = state.currentVersion ? 'v' + state.currentVersion : '';
    switch (state.phase) {
      case 'checking':
        setRow('正在检查…', true, '正在多线路检查新版本（GitHub 直连 + 镜像）…');
        break;
      case 'available':
        setRow('检查更新', false, '发现新版本 v' + (state.version || '') + '，可在弹窗中下载');
        break;
      case 'downloading':
        setRow('正在下载…', true, '正在下载 v' + (state.version || '') + ' … ' + (state.percent || 0) + '%');
        break;
      case 'ready':
        setRow('检查更新', false, 'v' + (state.version || '') + ' 已就绪，重启后生效');
        break;
      case 'latest':
        setRow('检查更新', false, '当前已是最新版本' + (cur ? '（' + cur + '）' : ''));
        break;
      case 'error':
        // v3.6.5 M1-1：签名类失败要写明「已阻止」而不是泛化的「更新失败」——
        // 否则用户会当成网络问题反复重试，而重试永远不会有结果。
        setRow('检查更新', false, state.sigFailed ? '已阻止（签名校验未通过）' : '更新失败，点击按钮重试');
        break;
      default:
        setRow('检查更新', false, cur ? '当前版本 ' + cur : '检查 Trim 是否有新版本');
    }
  }

  // ---------------- 状态机分发 ----------------
  function render() {
    switch (state.phase) {
      case 'idle':
        closeModal();
        break;
      case 'checking':
        // 后台静默检查不弹检查中弹窗；available 到达时自然弹窗
        if (activeManual) openModal('checking');
        break;
      case 'available':
        openModal('available');
        break;
      case 'downloading':
        openModal('downloading');
        fillDownload();
        break;
      case 'ready':
        openModal('ready');
        break;
      case 'latest':
        closeModal();
        if (activeManual) toast('success', '当前已是最新版本' + (state.currentVersion ? '（v' + state.currentVersion + '）' : ''));
        break;
      case 'error':
        // 后台静默检查的网络抖动（国内访问 GitHub 常见）不打扰用户；
        // 手动检查或弹窗已开（例如下载失败）才显性报错。
        if (activeManual || ctrl) openModal('error');
        break;
    }
    syncRow();
  }

  // ---------------- 手动检查 ----------------
  async function manualCheck() {
    if (!window.api || !window.api.updater) {
      toast('info', '当前环境不支持自动更新');
      return;
    }
    pendingManual = true;
    let res = null;
    try {
      res = await window.api.updater.check();
    } catch (e) {
      res = { skipped: false, error: e && e.message };
    }
    // 开发环境/重复检查被主进程短路时没有状态回流，直接在此恢复行状态并提示
    if (res && res.skipped) {
      pendingManual = false;
      activeManual = false;
      state.phase = res.reason === 'dev' ? 'idle' : state.phase;
      if (res.reason === 'dev') {
        state.phase = 'idle';
        syncRow();
        toast('info', '开发环境不检查更新（仅 NSIS 安装版支持自动更新）');
      } else if (res.reason === 'already-checking') {
        toast('info', '正在检查中，请稍候');
      }
    } else if (res && res.ok === false && (state.phase === 'idle' || state.phase === 'checking')) {
      // error 事件通常已回流；极端情况下回流丢失时兜底提示（已在 error 态则不重复渲染）
      state.phase = 'error';
      state.message = res.error || '检查更新失败';
      activeManual = true; // 手动触发的失败需要显性弹窗
      pendingManual = false;
      render();
      activeManual = false;
    }
  }

  // ---------------- 初始化 ----------------
  function init() {
    rowBtn = document.getElementById('btnCheckUpdate');
    rowHint = document.getElementById('updaterCheckHint');
    if (!rowBtn || !window.api || !window.api.updater) return; // 优雅降级

    // v2.6.0（P2-8）：更新镜像偏好下拉（主进程返回可选项与当前值，持久化在数据目录）
    const mirrorSelect = document.getElementById('updaterMirrorSelect');
    const mirrorHint = document.getElementById('updaterMirrorHint');
    if (mirrorSelect && window.api.updater.getMirror) {
      window.api.updater.getMirror().then(cfg => {
        if (!cfg || !Array.isArray(cfg.options)) return;
        // 主进程线路清单为准（新增镜像只改 updater.js 与此处渲染，无需改 HTML）
        mirrorSelect.innerHTML = '';
        cfg.options.forEach(opt => {
          const el = document.createElement('option');
          el.value = opt.id;
          el.textContent = opt.label;
          mirrorSelect.appendChild(el);
        });
        mirrorSelect.value = cfg.mirror || 'auto';
      }).catch(() => {});
      mirrorSelect.addEventListener('change', () => {
        const id = mirrorSelect.value || 'auto';
        try {
          window.api.updater.setMirror(id).then(r => {
            if (r && r.ok) {
              if (mirrorHint) mirrorHint.textContent = id === 'auto'
                ? 'GitHub 直连失败时自动回退镜像线路（下载内容经哈希校验）'
                : '已固定线路；下载内容仍经 latest.yml 哈希强校验，镜像只是传输通道';
              toast('success', '更新镜像偏好已保存');
            } else {
              toast('error', '镜像偏好保存失败');
            }
          }).catch(() => toast('error', '镜像偏好保存失败'));
        } catch (_) { /* 预览模式无 API */ }
      });
    }

    unbind = window.api.updater.onState(s => {
      if (!s || !s.phase) return;
      if (s.phase === 'checking') activeManual = pendingManual;
      Object.assign(state, s);
      render();
      // 终态后清掉本轮手动标记（available→下载→ready 期间弹窗保持，不受影响）
      if (s.phase === 'latest' || s.phase === 'error' || s.phase === 'idle') {
        pendingManual = false;
        activeManual = false;
      }
    });

    rowBtn.addEventListener('click', manualCheck);

    // 设置页行展示当前版本（与 app.js loadAppInfo 同源，独立获取避免时序耦合）
    if (window.api.app && window.api.app.getInfo) {
      window.api.app.getInfo().then(info => {
        if (info && info.version) {
          state.currentVersion = info.version;
          if (state.phase === 'idle') syncRow();
        }
      }).catch(() => {});
    }

    window.addEventListener('beforeunload', () => {
      try { unbind && unbind(); } catch (_) {}
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
