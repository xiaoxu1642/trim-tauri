// liquid-glass.js - 全局「液态玻璃」引擎 3.0（表面实色化后仅存交互层）
// 模式（P2-13 起真源在后端 settings.json 的 `liquidMotion` 键；localStorage
// 'trim-liquid-motion' 仅是首帧镜像/迁移来源；旧值 refract 自动迁移为 standard）。
// 选项三档（2026-10-09 用户裁定）：full / standard / off —— frost 从选项退役
// （太不明显），仅保留为环境自适应的内部降级档（电池/系统关透明时自动落入）。
// 表面实色化（方案 v1.6 §5.6）后各档语义收敛为纯交互差异：
//   full     = 分段栏弹簧滑块 + 按钮/次级按钮指针弹性形变(.lg-elastic)
//   standard = 仅分段栏弹簧滑块
//   frost    = 环境自适应内部档（电池/系统关透明时由 applyEnv 以 persist:false 落入），
//              与 standard 同效（磨砂/backdrop 写入段已随实色化退役）
//   off      = 隐藏滑块、摘除弹性形变，恢复实底选中态
// 折射位移贴图 / SVG 滤镜链 / backdrop-filter 写入 / WebGL 弹层焦散已整链退役：
// 表面全部实色后按钮与浮层不再「看穿身后内容」，滤镜与焦散失去作用对象。
// 性能护栏沿用：弹性形变只动 transform 变量（两趟读写纪律），滑块挂载带
// 120ms 节流与 MutationObserver 跟挂；prefers-reduced-motion 时停用形变。
(function () {
  'use strict';

  const MODE_KEY = 'trim-liquid-motion';
  const MODES = ['full', 'standard', 'frost', 'off'];
  const LEGACY_MODE_MAP = { refract: 'standard' };

  // v3.2.0（侧边岛玻璃选中滑块）：#sidebar 纳入滑块引擎，.nav-item 作为 tab——
  // 点击导航时选中块从旧项纵向平滑滑到新项（弹簧回弹 + 轻微挤压），替换硬切背景
  const BAR_SELECTOR = '.filter-tabs, .maint-tabs, #sidebar';
  const TAB_SELECTOR = '.filter-tab, .maint-tab, .nav-item';
  // 弹性形变名单（full 档 .lg-elastic）。2026-10-14 像素实测曾把按钮退出折射——
  // 实色化后折射已不存在，名单只剩「谁参与指针弹性形变」一个语义。
  const BUTTON_SELECTOR = '.btn-primary, .btn-accent, .btn-secondary';
  // 指针弹性激活区：光标距元素边缘多少 px 内开始形变
  const ELASTIC_ZONE = 160;
  const ELASTICITY = 0.12;

  let mode = 'full';
  let reduceMotion = false;
  // v2.8.0：环境自适应状态（会话级降级，不改用户存储的偏好）
  let envBattery = false;        // 电池供电：full/standard → frost
  let envNoTransparency = false; // 系统关闭「透明效果」：强制 frost

  const states = new Map();      // bar -> { thumb, mo, raf, lastX/Y/W/H, mount }（分段栏滑块）
  const elasticEls = new Set();  // full 模式参与弹性形变的按钮

  // P2-13（2026-10-09）：真源迁后端 settings.json 的 `liquidMotion` 键（AGENTS §0.2）；localStorage 降级为「同步初值
  // + 迁移来源 + 镜像」—— 档位不能在 init 等 IPC，否则首帧闪默认态；后端回读只做采纳/迁移，且晚于首帧也不推翻已渲染的档位。
  // 2026-10-09 用户裁定：磨砂档从**选项**退役（太不明显，与标准几乎不可辨），选项只剩完整/标准/关闭三档；frost 仍保留为
  // 环境自适应内部档（电池供电/系统关透明时由 applyEnv 以 persist:false 落入，不写用户偏好）。存量 frost 偏好按 standard 归一。
  const USER_MODES = ['full', 'standard', 'off'];
  let modePref = readLsMode();
  let modePrefDirty = false;

  function normalizeUserPref(v) {
    if (v === 'frost') return 'full';
    if (v && LEGACY_MODE_MAP[v]) return LEGACY_MODE_MAP[v];
    return USER_MODES.indexOf(v) > -1 ? v : 'full';
  }

  function readLsMode() {
    try {
      return normalizeUserPref(localStorage.getItem(MODE_KEY));
    } catch (e) { return 'full'; }
  }

  function readStoredMode() { return modePref; }
  // 用户偏好档（下拉显示用）：与 getMode 的「实际生效档」不同 —— 环境降级
  //（电池/系统关透明 → frost）只改生效档，下拉必须仍显示用户选的那一档。
  function getUserMode() { return modePref; }

  function persistMode(m) {
    modePref = m;
    modePrefDirty = true;
    try { localStorage.setItem(MODE_KEY, m); } catch (e) { /* 镜像写失败不影响（真源在后端） */ }
    try {
      window.api?.settings?.setPref?.('liquidMotion', m)?.catch?.(() => {});
    } catch (e) { /* 真源写入失败按镜像工作，不打断档位切换 */ }
  }

  // 设置页档位下拉与真源对齐：app.js 初始化时读 getUserMode()，后端采纳若晚于它，
  // 下拉会停在旧值——这里补一次同步（下拉不存在时静默跳过，本引擎四窗共用）。
  function syncModeSelect() {
    const sel = document.getElementById('liquidMotionSelect');
    if (sel && sel.value !== modePref) sel.value = modePref;
  }

  // 后端真源回读：合法档位 ⇒ 采纳并即时应用；无值/坏值 ⇒ 把本地镜像一次性迁移上去。
  // modePrefDirty 时跳过采纳（读回的是写入前的旧值，会覆盖用户刚做的切换）。
  (async function syncModePref() {
    try {
      const resp = await window.api?.settings?.getPrefs?.();
      if (!resp || !resp.success || modePrefDirty) return;
      const v = resp.data?.liquidMotion;
      if (typeof v === 'string' && (MODES.indexOf(v) > -1 || LEGACY_MODE_MAP[v])) {
        const m = normalizeUserPref(v);
        if (m !== modePref) {
          modePref = m;
          try { localStorage.setItem(MODE_KEY, m); } catch (e) { /* 镜像写失败不影响（真源已就位） */ }
          // init 未跑时 readStoredMode 会取到新值，无需重复应用；已 init 则即时换档
          if (document.documentElement.classList.contains('lg-init')) setMode(m, { persist: false });
        }
        syncModeSelect();
      } else {
        persistMode(modePref); // 迁移：后端没有值，把本地现值推上去
      }
    } catch (e) { /* 真源不可用按本地镜像工作 */ }
  })();

  function prefersReduceMotion() {
    if (window.ds && typeof window.ds.reducedMotion === 'function') return !!window.ds.reducedMotion();
    if (window.ds && typeof window.ds.reducedMotionFallback === 'function') return !!window.ds.reducedMotionFallback();
    return true;
  }

  function normalizeMode(v) {
    if (v && LEGACY_MODE_MAP[v]) return LEGACY_MODE_MAP[v];
    return MODES.indexOf(v) > -1 ? v : 'full';
  }

  // 弹性形变层：按档位把 .lg-elastic 收敛到名单成员上（幂等，可反复调用）。
  // 旧引擎经 commitGlass 逐元素挂载；实色化后没有滤镜要配额，直接全量收敛。
  // 动态渲染的按钮（优化中心看板等）由 MutationObserver 触发本函数补挂。
  function syncElastics() {
    const want = mode === 'full' && !reduceMotion;
    document.querySelectorAll(BUTTON_SELECTOR).forEach((el) => {
      const has = el.classList.contains('lg-elastic');
      if (want && !has) {
        el.classList.add('lg-elastic');
        elasticEls.add(el);
      } else if (!want && has) {
        el.classList.remove('lg-elastic');
        elasticEls.delete(el);
        resetElasticVars(el);
        el.__lgActive = false;
      }
    });
    // 已脱离文档的成员就地出册（避免 Set 无界增长）
    elasticEls.forEach((el) => {
      if (!el.isConnected) { elasticEls.delete(el); return; }
      if (!want && el.classList.contains('lg-elastic')) {
        el.classList.remove('lg-elastic');
        resetElasticVars(el);
        el.__lgActive = false;
      }
    });
  }

  // 动态 UI 跟挂节流：弹窗 / 各页动态渲染的按钮出现后补收敛（与旧 scheduleScan 同 120ms）
  let elasticScanTimer = 0;
  function scheduleElasticScan() {
    if (elasticScanTimer) return;
    elasticScanTimer = setTimeout(() => {
      elasticScanTimer = 0;
      syncElastics();
    }, 120);
  }

  // 指针弹性形变 + 高光跟随（full 模式）
  let elasticRaf = 0;
  const pointer = { x: -1e5, y: -1e5 };

  function resetElasticVars(el) {
    el.style.removeProperty('--lg-sx');
    el.style.removeProperty('--lg-sy');
    el.style.removeProperty('--lg-tx');
    el.style.removeProperty('--lg-ty');
    el.style.removeProperty('--lg-press');
  }

  // F5-M07：两趟化——先把所有可见成员的盒子读完，再统一写 CSS 变量。
  // 旧版每个元素「读 rect → 写 --lg-sx/sy/tx/ty」交错，下一圈次的读会被上一圈次的写判脏，
  // N 个可见按钮就是每帧 N 次同步样式重算（xtable 的批量写同款纪律）。
  // 等价性前提：--lg-* 只参与 .lg-elastic 的 transform（main.css），transform 不参与布局，
  // 元素 i 的行内写不会改变元素 j 的 rect ⇒ 两趟与逐元素交错读到同一组盒子，形变终值不变。
  // 保留阅读顺序与早退分支：脱离文档的成员就地出册，零宽（隐藏页）元素跳过不写。
  function updateElastics() {
    elasticRaf = 0;
    if (mode !== 'full') return;
    const boxes = [];
    elasticEls.forEach((el) => {
      if (!el.isConnected) { elasticEls.delete(el); return; }
      const r = el.getBoundingClientRect();
      if (!r.width) return;
      boxes.push({ el: el, r: r });
    });
    for (let i = 0; i < boxes.length; i++) {
      const el = boxes[i].el;
      const r = boxes[i].r;
      const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      const dx = pointer.x - cx, dy = pointer.y - cy;
      const edgeX = Math.max(0, Math.abs(dx) - r.width / 2);
      const edgeY = Math.max(0, Math.abs(dy) - r.height / 2);
      const edge = Math.sqrt(edgeX * edgeX + edgeY * edgeY);
      if (edge > ELASTIC_ZONE) {
        if (el.__lgActive) { resetElasticVars(el); el.__lgActive = false; }
        continue;
      }
      const fadeIn = 1 - edge / ELASTIC_ZONE;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const nx = dx / dist, ny = dy / dist;
      const intensity = Math.min(dist / 300, 1) * ELASTICITY * fadeIn;
      const sx = 1 + Math.abs(nx) * intensity * 0.3 - Math.abs(ny) * intensity * 0.15;
      const sy = 1 + Math.abs(ny) * intensity * 0.3 - Math.abs(nx) * intensity * 0.15;
      const tx = dx * ELASTICITY * 0.06 * fadeIn;
      const ty = dy * ELASTICITY * 0.06 * fadeIn;
      el.__lgActive = true;
      el.style.setProperty('--lg-sx', sx.toFixed(4));
      el.style.setProperty('--lg-sy', sy.toFixed(4));
      el.style.setProperty('--lg-tx', tx.toFixed(2) + 'px');
      el.style.setProperty('--lg-ty', ty.toFixed(2) + 'px');
    }
  }

  function onPointerMove(e) {
    pointer.x = e.clientX;
    pointer.y = e.clientY;
    if (elasticRaf) return;
    elasticRaf = requestAnimationFrame(updateElastics);
  }

  // 指针高光曾走 CSS 变量：onPointerOver 往 .lg-elastic 写 --lg-mx/--lg-my，但全仓 var()
  // 消费 0 次（光斑实际由 spotlight.js 的 --spot-x/--spot-y 驱动）——写入点与 pointerover
  // 监听整条退役（审查 F1a-L08：死跨语言 API 会骗过「引用−定义」正向差集）。
  function onPressIn(e) {
    const el = e.target && e.target.closest ? e.target.closest('.lg-elastic') : null;
    if (el) el.style.setProperty('--lg-press', '0.96');
  }
  function onPressOut(e) {
    const el = e.target && e.target.closest ? e.target.closest('.lg-elastic') : null;
    if (el) el.style.removeProperty('--lg-press');
  }

  // 分段栏滑块（贴图换成物理折射版的时代已结束，保留弹簧跟随）
  // v3.2.0：#sidebar 也是 bar，active 查找同步覆盖 .nav-item
  function findActiveTab(bar) {
    // 侧边栏：测速父项在其子页（diskbench/netcheck/netspeed）也带 .active（分组高亮），
    // 滑块必须贴合真实菜单项——排除带 data-nav-toggle 的父级条目
    if (isSidebarBar(bar)) {
      return bar.querySelector('.nav-item.active:not([data-nav-toggle])');
    }
    // 注意：不能拼成 '.filter-tab, .maint-tab.active'——选择器列表是并集，
    // 会命中任意第一个 .filter-tab；必须对两种类分别要求 .active
    return bar.querySelector('.filter-tab.active, .maint-tab.active');
  }

  // 侧边栏 bar（纵向滑动、小圆角）
  function isSidebarBar(bar) { return bar && bar.id === 'sidebar'; }

  function createThumb(bar, state) {
    const thumb = document.createElement('span');
    thumb.className = 'lg-thumb';
    // v3.2.0：侧边栏滑块挂进 .nav-scroll 滚动容器内——nav 纵向滚动时滑块随内容
    // 自然跟随（.nav-scroll 已 position:relative），免去 scrollTop 逐帧修正
    const mount = isSidebarBar(bar) ? (bar.querySelector('.nav-scroll') || bar) : bar;
    mount.appendChild(thumb);
    state.thumb = thumb;
    state.mount = mount; // placeThumb 判「active 是否在本包含块内」用
    // F5-M06：「关闭」档建节点时就收起——挂载到位到首个 rAF 之间不许露出空壳滑块。
    // 之后的可见性一律由 placeThumb 单点决定，这里只给初始态。
    if (mode === 'off') thumb.style.display = 'none';
    return thumb;
  }

  function placeThumb(bar, state, animate) {
    const thumb = state.thumb;
    if (!thumb) return;
    // F5-M06：「关闭」档必须整枚撤掉滑块。.lg-thumb 自带 CSS 实底胶囊，
    // 留着 display 就是一枚实心块，与「off = 隐藏滑块」的档位语义相反。
    // 判据放这里、先于下面的常态 display 复位：refreshBars / init 曾各自写 display=none，
    // 都被本函数的 display='' 掀开，关闭态因此长期复现。
    if (mode === 'off') {
      thumb.style.display = 'none';
      return;
    }
    const tab = findActiveTab(bar);
    const vertical = isSidebarBar(bar);
    // 2026-10-15（目检：「设置」页底部多出游离滑块）：「设置」在 footer、不在滑块
    // 包含块 .nav-scroll 内，offsetTop 按 .sidebar 口径算出的越界坐标会把滑块摆到列表
    // 底部并撑出可滚动溢出。目标不在包含块里 = 无位可贴：隐藏；回到普通项时恢复。
    if (vertical && (!tab || !(state.mount || bar).contains(tab))) {
      thumb.style.display = 'none';
      return;
    }
    if (!tab) return;
    thumb.style.display = '';
    const x = tab.offsetLeft;
    const y = tab.offsetTop;
    const w = tab.offsetWidth;
    const h = tab.offsetHeight;
    if (!w || !h) return; // 页面隐藏中，等下次刷新
    // 横向 tab 栏保持胶囊；侧边栏菜单项是小圆角（--radius-medium），非胶囊
    const radius = vertical ? 10 : h / 2;

    // v3.2.1（滑块误挤压修复·方案A）：目标坐标与尺寸与上次完全一致时不加挤压类——
    // 修复「点磁盘清理子分段时 refreshAll(true) 让 #sidebar 滑块无意义鼓一下」：
    // 位置零位移却从 scaleX(1) 过渡到 scaleX(1.05) 再回弹。切菜单项时坐标必变，动画照旧。
    const unchanged = state.lastX === x && state.lastY === y &&
                      state.lastW === w && state.lastH === h;

    if (!animate) thumb.classList.add('lg-no-anim');

    // 移动中轻微拉伸（液态挤压感），落位后由 transitionend 回弹恢复
    if (animate && !unchanged && !document.body.classList.contains('lg-reduce-motion')) {
      thumb.classList.add('lg-moving');
    }

    // v3.2.0：纵向侧边栏两轴位移都走 transform（GPU 加速），不再直接写 top（瞬移无过渡）；
    // 横向 tab 栏 offsetTop 恒 0，维持原 top 写法兼容
    if (vertical) {
      thumb.style.top = '0px';
      thumb.style.setProperty('--lg-y', y + 'px');
      state.lastY = y;
    } else {
      // 防御性清零：重建恢复路径（上方 MutationObserver）曾给横向栏残留 --lg-y，
      // transform 与 top 双重叠加会把滑块压低一个 padding；这里显式归零自愈
      thumb.style.setProperty('--lg-y', '0px');
      thumb.style.top = y + 'px';
    }
    thumb.style.width = w + 'px';
    thumb.style.height = h + 'px';
    thumb.style.setProperty('--lg-x', x + 'px');
    thumb.style.borderRadius = radius + 'px';
    state.lastX = x;
    state.lastY = y;
    state.lastW = w;
    state.lastH = h;

    // backdrop-filter 写入段已随表面实色化退役（方案 v1.6 §5.6）：
    // 滑块底色由 .lg-thumb 的实色 CSS 自证，这里只管位置与弹簧。

    if (!animate) {
      void thumb.offsetWidth; // 跳过一次过渡后再恢复动画
      requestAnimationFrame(() => thumb.classList.remove('lg-no-anim'));
    } else if (!unchanged) {
      // 位置未变时不挂监听（无过渡可触发；避免连续快速点击叠 once 监听器与兜底定时器）
      thumb.addEventListener('transitionend', (ev) => {
        if (ev.propertyName === 'transform') thumb.classList.remove('lg-moving');
      }, { once: true });
      // 兜底：transitionend 可能因标签页隐藏等被吞掉
      setTimeout(() => thumb.classList.remove('lg-moving'), 600);
    }
  }

  function schedulePlace(bar, animate) {
    const state = states.get(bar);
    if (!state) return;
    if (state.raf) cancelAnimationFrame(state.raf);
    state.raf = requestAnimationFrame(() => {
      state.raf = 0;
      placeThumb(bar, state, animate);
    });
  }

  function mountBar(bar) {
    if (states.has(bar)) return;
    const state = { thumb: null, moved: false, mo: null };
    states.set(bar, state);
    bar.classList.add('lg-bar');
    createThumb(bar, state);

    // 维护/快捷指令页会整体重渲染栏内容：滑块被清掉后从原位置滑向新目标，
    // 保留液态跟随感；其余变化静默重定位
    // 审查 v2-M22（v1 L14 未修）：观察者句柄必须存进 state —— 原来 new 完就丢，
    // 栏被换掉后旧 observer 还盯着一个已离开的子树，且 states 条目永不减少。
    state.mo = new MutationObserver(() => {
      if (!bar.isConnected) return;                 // 栏已离开，静默退出（真正的回收在 detachBar）
      if (!bar.contains(state.thumb)) {
        createThumb(bar, state);
        if (typeof state.lastX === 'number') {
          state.thumb.classList.add('lg-no-anim');
          state.thumb.style.setProperty('--lg-x', state.lastX + 'px');
          // v3.2.0：侧边栏纵向坐标一并恢复（top=0 + --lg-y），否则重建后瞬跳回顶部。
          // 修复（目检实锤）：此恢复只属于纵向栏——横向栏的 Y 走 top（placeThumb 会重写），这里若也无条件写 --lg-y=lastY，
          // 随后的 placeThumb 只写 top 不清 --lg-y ⇒ top+transform 双重叠加、横向滑块整体下移一个 padding（维护/快捷指令页重渲染必现）。
          if (isSidebarBar(bar) && typeof state.lastY === 'number') {
            state.thumb.style.top = '0px';
            state.thumb.style.setProperty('--lg-y', state.lastY + 'px');
          }
          void state.thumb.offsetWidth;
          requestAnimationFrame(() => {
            state.thumb?.classList.remove('lg-no-anim');
            // LG-5：统一读 reduceMotion 状态量（由 init/syncReduceMotion 维护），不再散落直查媒体查询
            schedulePlace(bar, !reduceMotion);
          });
          return;
        }
      }
      schedulePlace(bar, false);
    });
    state.mo.observe(bar, { childList: true });

    schedulePlace(bar, false);
  }

  // 审查 v2-M22（v1 L14 未修部分）：states 此前**全文无 delete** —— 维护页/快捷指令页每次重渲染都会换掉整条 bar，旧条目
  //（连同 bar、thumb 子树、MutationObserver）被 Map 永久持有，切页越多攒越多。
  // 回收必须与 mountBar 严格配对：取消在途 rAF → 断观察者 → 摘 thumb → 删条目。
  function detachBar(bar, state) {
    if (state.raf) cancelAnimationFrame(state.raf);
    state.raf = 0;
    if (state.mo) { state.mo.disconnect(); state.mo = null; }
    if (state.thumb) state.thumb.remove();
    state.thumb = null;
    bar.classList.remove('lg-bar');
    states.delete(bar);
  }

  function mountAll() {
    document.querySelectorAll(BAR_SELECTOR).forEach((bar) => {
      if (!bar.querySelector(TAB_SELECTOR)) return;
      if (!bar.querySelector(TAB_SELECTOR + '.active')) return;
      mountBar(bar);
    });
  }

  function refreshBars(animate) {
    // 补挂迟渲染的栏（如优化中心分类栏由 API 回调后渲染，init 时还没有标签）
    mountAll();
    // 审查 v2-M22：先回收已离开文档的栏（切页会整条换掉 bar 节点）。
    states.forEach((state, bar) => {
      if (!bar.isConnected) detachBar(bar, state);
    });
    states.forEach((state, bar) => {
      if (!state.thumb) return;
      // F5-M06：这里曾经写 display=none（off 档），但紧接着 schedulePlace 的 placeThumb
      // 在常态分支无条件写 display=''，把关闭态掀开。可见性由 placeThumb 单点决定。
      schedulePlace(bar, animate !== false);
    });
  }

  // 模式切换
  function applyModeClass() {
    const body = document.body;
    MODES.forEach((m) => body.classList.toggle('lg-mode-' + m, mode === m));
  }

  function setMode(next, opts) {
    mode = normalizeMode(next);
    // v2.8.0：环境自适应降级走 persist:false——用户存的偏好不被覆盖，环境恢复后自动回弹
    if (!opts || opts.persist !== false) persistMode(mode);
    applyModeClass();
    // off/frost 不再需要拆滤镜（折射段已退役）：弹性收敛 + 滑块重定位即可
    syncElastics();
    refreshBars(false);
  }

  // v2.8.0：环境自适应——按电池/系统透明开关计算生效档位并应用
  function effectiveMode() {
    const user = readStoredMode();
    if (envNoTransparency) return 'frost';
    if (envBattery && (user === 'full' || user === 'standard')) return 'frost';
    return user;
  }
  function applyEnv() {
    const eff = effectiveMode();
    if (eff !== mode) setMode(eff, { persist: false });
  }

  function getMode() { return mode; }

  // 事件接线
  let bodyMo = null;
  // F5-L12：onXxx 同步返回 unsubscribe（tauri-api.js 的事件契约），旧实现丢弃返回值 ⇒
  // 订阅永不退订，与同仓 updater-ui.js 存下来在 beforeunload 解绑的口径分叉。
  let offEnvState = null;

  // LG-5（2026-09-15）：reduced-motion 实时求值——原实现 init 时读一次固化，
  // 运行中切换系统「减少动态效果」偏好永不生效（与同库 spotlight v4-M1 修复口径一致）。
  function bindReducePointerListeners(add) {
    if (add) {
      document.addEventListener('pointermove', onPointerMove, { passive: true });
      document.addEventListener('pointerdown', onPressIn, true);
      document.addEventListener('pointerup', onPressOut, true);
      document.addEventListener('pointercancel', onPressOut, true);
    } else {
      document.removeEventListener('pointermove', onPointerMove, { passive: true });
      document.removeEventListener('pointerdown', onPressIn, true);
      document.removeEventListener('pointerup', onPressOut, true);
      document.removeEventListener('pointercancel', onPressOut, true);
    }
  }
  function syncReduceMotion() {
    const was = reduceMotion;
    reduceMotion = prefersReduceMotion();
    document.body.classList.toggle('lg-reduce-motion', reduceMotion);
    if (reduceMotion !== was) bindReducePointerListeners(!reduceMotion);
    // reduce 翻转两个方向都由 syncElastics 收敛（want = full && !reduce）
    if (reduceMotion !== was) syncElastics();
  }

  function init() {
    mode = readStoredMode();
    reduceMotion = prefersReduceMotion();
    document.documentElement.classList.add('lg-init');
    applyModeClass();

    // v2.8.0：环境自适应接线——电池供电广播 + 系统透明效果开关媒体查询
    try {
      const trMQ = window.matchMedia('(prefers-reduced-transparency: reduce)');
      envNoTransparency = trMQ.matches;
      const onTrChange = (e) => { envNoTransparency = !!(e && e.matches); applyEnv(); };
      if (typeof trMQ.addEventListener === 'function') trMQ.addEventListener('change', onTrChange);
      else if (typeof trMQ.addListener === 'function') trMQ.addListener(onTrChange);
    } catch (e) { /* 老环境无该媒体查询，忽略 */ }

    // LG-5（2026-09-15）：系统「减少动态效果」偏好运行中切换 → 实时重求值并按需挂/摘指针监听
    try {
      const rmMQ = window.ds?.reducedMotionQuery?.();
      if (rmMQ) {
        const onRmChange = () => syncReduceMotion();
        if (typeof rmMQ.addEventListener === 'function') rmMQ.addEventListener('change', onRmChange);
        else if (typeof rmMQ.addListener === 'function') rmMQ.addListener(onRmChange);
      }
    } catch (e) { /* 老环境无该媒体查询，忽略 */ }
    if (window.api?.appearance?.getEnv) {
      window.api.appearance.getEnv().then((env) => {
        if (!env) return;
        envBattery = !!env.onBattery;
        if (typeof env.transparencyOff === 'boolean') envNoTransparency = env.transparencyOff;
        applyEnv();
      }).catch(() => {});
    }
    if (window.api?.appearance?.onEnvState) {
      offEnvState = window.api.appearance.onEnvState((env) => {
        if (!env) return;
        envBattery = !!env.onBattery;
        if (typeof env.transparencyOff === 'boolean') envNoTransparency = env.transparencyOff;
        applyEnv();
      });
      // 每文档至多一条环境订阅，随文档卸载释放（不靠 GC 兜闭包与 Tauri 侧 listener id）
      window.addEventListener('beforeunload', function () {
        try { if (offEnvState) offEnvState(); } catch (e) { /* 退订失败不阻塞卸载 */ }
        offEnvState = null;
      }, { once: true });
    }

    // 点击任意分段标签：栏内 active 切换完成后，滑块带弹簧动画跟随；
    // 点击也可能渲染新按钮（优化中心等），顺带调度一次弹性收敛
    document.addEventListener('click', (e) => {
      const tab = e.target && e.target.closest ? e.target.closest(TAB_SELECTOR) : null;
      if (tab) {
        const bar = tab.closest(BAR_SELECTOR);
        // LG-5：同上，统一读 reduceMotion 状态量
        if (bar && states.has(bar)) schedulePlace(bar, !reduceMotion);
      }
      scheduleElasticScan();
    }, true);

    // LG-5（2026-09-15）：统一走 syncReduceMotion 同一口径——按初始值挂指针监听，
    // 运行中偏好切换由上面的 matchMedia change 监听接管（原静态块读一次即固化）
    document.body.classList.toggle('lg-reduce-motion', reduceMotion);
    bindReducePointerListeners(!reduceMotion);

    // 字体加载完成会改变标签/按钮尺寸，重新对齐
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(() => { refreshBars(false); });
    }

    window.addEventListener('resize', () => { refreshBars(false); });

    // 动态 UI 跟挂（弹窗 / 动态渲染的按钮）：只喂弹性收敛，不再有玻璃扫描
    bodyMo = new MutationObserver(scheduleElasticScan);
    bodyMo.observe(document.body, { childList: true, subtree: true });

    mountAll();
    syncElastics();
    // F5-M06：关闭态的可见性现由 placeThumb 的 off 分支负责，init 不再重复写 display。
  }

  window.liquidBar = {
    init, mountAll, refreshAll: refreshBars, setMode, getMode, getUserMode,
    // 2.0 扩展：手动触发收敛（供动态渲染模块调用，可选项）
    rescan: scheduleElasticScan,
    // 诊断：内部状态快照（弹性成员 / 栏位 / 环境自适应）
    debug: () => ({
      mode, reduceMotion, elastic: elasticEls.size,
      bars: states.size,
      env: { battery: envBattery, noTransparency: envNoTransparency }
    })
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
