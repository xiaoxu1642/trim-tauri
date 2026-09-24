// liquid-glass.js - 全局「液态玻璃」引擎 2.0
// 模式（localStorage 'winclean-liquid-motion'，四档；旧值 refract 自动迁移为 standard）。
// 材质语义对齐 Apple Liquid Glass（docs规范/update/2026-09-14 五方案评估·B1）：
//   full     ≈ clear+ ：完整液态玻璃——分段栏滑块 + 按钮 + 弹层 SVG 物理折射（斯涅尔定律位移贴图）
//              + RGB 三通道边缘色散 + 高光贴图 + 指针弹性形变 + WebGL 弹层焦散高光
//   standard ≈ regular：标准液态玻璃——覆盖面同 full，但单通道折射、无色散 / 形变 / WebGL
//   frost    = regular 降级：磨砂玻璃，仅 backdrop blur（CSS 驱动），无折射滤镜
//   off      = 实底：隐藏滑块、恢复实底按钮，不注入任何滤镜
// 技术来源：
//   - 位移贴图：圆角矩形角环 + 斯涅尔折射轮廓（厚度 / 斜边宽 / 折射率），参考 liquid实现2
//   - 色散：R/G/B 三次 feDisplacementMap 不同 scale 后按 screen 混合，参考 liquid实现3
//   - 高光：独立 specular 贴图在滤镜链内合成，参考 liquid实现2
//   - 指针弹性形变：边缘激活区内的方向性缩放 + 平移，参考 liquid实现3
// 能力检测失败（backdrop-filter 不支持引用 SVG 滤镜）自动降级 frost。
// 性能护栏：贴图/滤镜按尺寸缓存复用；折射按环带像素量计费 + 面积兜底（B2）；
//           折射元素数量与滤镜桶数量有上限；prefers-reduced-motion 时禁用指针形变与 WebGL 动画。
(function () {
  'use strict';

  const MODE_KEY = 'winclean-liquid-motion';
  const MODES = ['full', 'standard', 'frost', 'off'];
  const LEGACY_MODE_MAP = { refract: 'standard' };

  // v3.2.0（侧边岛玻璃选中滑块）：#sidebar 纳入滑块引擎，.nav-item 作为 tab——
  // 点击导航时选中玻璃块从旧项纵向平滑滑到新项（弹簧回弹 + 轻微挤压），替换硬切背景
  const BAR_SELECTOR = '.filter-tabs, .maint-tabs, #sidebar';
  const TAB_SELECTOR = '.filter-tab, .maint-tab, .nav-item';
  // 折射玻璃按钮：主题色实底在液态模式下由 CSS 换成浅色玻璃底（main.css 液态玻璃段），JS 负责折射滤镜
  const BUTTON_SELECTOR = '.btn-primary, .btn-accent, .btn-secondary';
  // v3 评估 C/L3：输入框与下拉纳入折射体系（field-input 同时挂在 input 与 select 上）。
  // 归类为 control：有折射、无弹性形变（输入中形变会干扰打字）、无 shimmer
  const INPUT_SELECTOR = '.field-input';
  // 折射池全量扫描目标（按钮 + 输入控件 + 浮层）
  const REFRACT_SELECTOR = BUTTON_SELECTOR + ', ' + INPUT_SELECTOR;
  // 悬浮玻璃层：统一弹窗 / 右键详情 / ds 下拉菜单（动态创建，由 MutationObserver 跟挂）。
  // v3.0 修复批次（B4 扩覆盖面）：--bg-card 透明化后 ds-menu 底色改由 CSS floor+blur
  // 兜底（main.css 菜单段），full/standard 档再由本引擎叠加折射与 shimmer
  const FLOATING_SELECTOR = '.usage-modal, .ctx-detail-modal, .ds-menu';
  // 折射元素上限：滤镜链是像素级操作，数量失控会掉帧，超出的退化为磨砂
  const MAX_REFRACT = 28;
  // 折射预算（v2 评估 B2 环带计费）：位移贴图只在边缘环带非零，主计费按环带像素量
  // ring ≈ 2×(w+h)×bezel（bezel 与 buildMaps 同式）——宽工具行/大卡片/弹层与方框同权，
  // 不再因整面积超限一刀切退化纯 blur（Apple 的玻璃主体恰是大面板）。
  // 但 feDisplacementMap 仍按元素整面积处理，故保留面积兜底防极端大面板
  const RING_BEZEL_MAX = 26;        // 与 buildMaps 的 bezel 上限一致
  const MAX_RING_PIXELS = 96000;    // 环带预算：420² 方框≈44k、1200×160 工具行≈24k、560×420 弹层≈18k
  const MAX_REFRACT_AREA = 352800;  // 面积兜底（≈594²）：主窗级整面板仍被挡

  function ringBezel(w, h, radius) {
    const r = Math.min(radius, w / 2, h / 2);
    return Math.max(3, Math.min(r * 0.9, Math.min(w, h) * 0.4, RING_BEZEL_MAX));
  }
  function withinRefractBudget(w, h, radius) {
    if (w * h > MAX_REFRACT_AREA) return false;
    return 2 * (w + h) * ringBezel(w, h, radius) <= MAX_RING_PIXELS;
  }
  // 指针弹性激活区：光标距元素边缘多少 px 内开始形变
  const ELASTIC_ZONE = 160;
  const ELASTICITY = 0.12;

  let mode = 'standard';
  let refractionSupported = true;
  let reduceMotion = false;
  // v2.8.0：玻璃质感参数（读自 main.css --glass-satur/--glass-bright，init 时取一次）
  // v3.0 修复批次：默认值与 token 同步收敛到 Apple 消色玻璃档（1.25/1.02）
  let glassSatur = 1.25;
  let glassBright = 1.02;
  // v2.8.0：环境自适应状态（会话级降级，不改用户存储的偏好）
  let envBattery = false;        // 电池供电：full/standard → frost
  let envNoTransparency = false; // 系统关闭「透明效果」：强制 frost

  const states = new Map();      // bar -> { thumb, filterId, mapW, mapH }（分段栏滑块）
  const glassStates = new Map(); // el  -> { kind, w, h, radius, blur, refract }
  const elasticEls = new Set();  // full 模式参与弹性形变的按钮
  let refractCount = 0;

  function readStoredMode() {
    try {
      const v = localStorage.getItem(MODE_KEY);
      if (v && LEGACY_MODE_MAP[v]) return LEGACY_MODE_MAP[v];
      return MODES.indexOf(v) > -1 ? v : 'standard';
    } catch (e) { return 'standard'; }
  }

  function persistMode(m) {
    try { localStorage.setItem(MODE_KEY, m); } catch (e) {}
  }

  function prefersReduceMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  function normalizeMode(v) {
    if (v && LEGACY_MODE_MAP[v]) return LEGACY_MODE_MAP[v];
    return MODES.indexOf(v) > -1 ? v : 'standard';
  }

  // ============ 位移贴图（斯涅尔折射轮廓） ============
  const mapCache = new Map(); // 'w x h r' -> { url, specUrl }
  const MAP_CACHE_MAX = 48;

  // convex squircle 表面高度函数：边缘曲率自然，比圆弧更接近真实玻璃倒角
  function surfaceHeight(x) {
    return Math.pow(1 - Math.pow(1 - x, 4), 0.25);
  }

  // 按斯涅尔定律计算边缘折射轮廓：入射角由表面斜率导出，折射率 ior 控制弯折强度
  function calculateRefractionProfile(glassThickness, bezelWidth, ior, samples) {
    samples = samples || 96;
    const eta = 1 / ior;
    function refract(nx, ny) {
      const dot = ny;
      const k = 1 - eta * eta * (1 - dot * dot);
      if (k < 0) return null;
      const sq = Math.sqrt(k);
      return [-(eta * dot + sq) * nx, eta - (eta * dot + sq) * ny];
    }
    const profile = new Float64Array(samples);
    for (let i = 0; i < samples; i++) {
      const x = i / samples;
      const y = surfaceHeight(x);
      const dx = x < 1 ? 0.0001 : -0.0001;
      const y2 = surfaceHeight(x + dx);
      const deriv = (y2 - y) / dx;
      const mag = Math.sqrt(deriv * deriv + 1);
      const ref = refract(-deriv / mag, -1 / mag);
      if (!ref) { profile[i] = 0; continue; }
      profile[i] = ref[0] * ((y * bezelWidth + glassThickness) / ref[1]);
    }
    return profile;
  }

  // 生成位移贴图：只在圆角矩形边缘环带内有位移，中心保持 128（零位移）
  function generateDisplacementCanvas(w, h, radius, bezelWidth, profile, maxDisp) {
    const c = document.createElement('canvas');
    c.width = Math.max(1, w);
    c.height = Math.max(1, h);
    const ctx = c.getContext('2d');
    const img = ctx.createImageData(c.width, c.height);
    const d = img.data;
    for (let i = 0; i < d.length; i += 4) {
      d[i] = 128; d[i + 1] = 128; d[i + 2] = 0; d[i + 3] = 255;
    }
    const r = Math.min(radius, c.width / 2, c.height / 2);
    const rSq = r * r, r1Sq = (r + 1) * (r + 1);
    const rBSq = Math.max(r - bezelWidth, 0) ** 2;
    const wB = c.width - r * 2, hB = c.height - r * 2;
    const S = profile.length;

    for (let y1 = 0; y1 < c.height; y1++) {
      for (let x1 = 0; x1 < c.width; x1++) {
        const x = x1 < r ? x1 - r : x1 >= c.width - r ? x1 - r - wB : 0;
        const y = y1 < r ? y1 - r : y1 >= c.height - r ? y1 - r - hB : 0;
        const dSq = x * x + y * y;
        if (dSq > r1Sq || dSq < rBSq) continue;
        const dist = Math.sqrt(dSq);
        const fromSide = r - dist;
        const op = dSq < rSq ? 1 : 1 - (dist - Math.sqrt(rSq)) / (Math.sqrt(r1Sq) - Math.sqrt(rSq));
        if (op <= 0 || dist === 0) continue;
        const cos = x / dist, sin = y / dist;
        const bi = Math.min(((fromSide / bezelWidth) * S) | 0, S - 1);
        const disp = profile[bi] || 0;
        const dX = (-cos * disp) / maxDisp, dY = (-sin * disp) / maxDisp;
        const idx = (y1 * c.width + x1) * 4;
        d[idx] = (128 + dX * 127 * op + 0.5) | 0;
        d[idx + 1] = (128 + dY * 127 * op + 0.5) | 0;
      }
    }
    ctx.putImageData(img, 0, 0);
    return c.toDataURL();
  }

  // 生成高光贴图：边缘环带上按固定光照角度高亮（滤镜链内合成，省一层 DOM）
  function generateSpecularCanvas(w, h, radius, bezelWidth, angle) {
    angle = angle != null ? angle : Math.PI / 3;
    const c = document.createElement('canvas');
    c.width = Math.max(1, w);
    c.height = Math.max(1, h);
    const ctx = c.getContext('2d');
    const img = ctx.createImageData(c.width, c.height);
    const d = img.data;
    const r = Math.min(radius, c.width / 2, c.height / 2);
    const rSq = r * r, r1Sq = (r + 1) * (r + 1);
    const rBSq = Math.max(r - bezelWidth * 2.5, 0) ** 2;
    const wB = c.width - r * 2, hB = c.height - r * 2;
    const sv = [Math.cos(angle), Math.sin(angle)];

    for (let y1 = 0; y1 < c.height; y1++) {
      for (let x1 = 0; x1 < c.width; x1++) {
        const x = x1 < r ? x1 - r : x1 >= c.width - r ? x1 - r - wB : 0;
        const y = y1 < r ? y1 - r : y1 >= c.height - r ? y1 - r - hB : 0;
        const dSq = x * x + y * y;
        if (dSq > r1Sq || dSq < rBSq) continue;
        const dist = Math.sqrt(dSq);
        const fromSide = r - dist;
        const op = dSq < rSq ? 1 : 1 - (dist - Math.sqrt(rSq)) / (Math.sqrt(r1Sq) - Math.sqrt(rSq));
        if (op <= 0 || dist === 0) continue;
        const cos = x / dist, sin = -y / dist;
        const dot = Math.abs(cos * sv[0] + sin * sv[1]);
        const edge = Math.sqrt(Math.max(0, 1 - (1 - fromSide) * (1 - fromSide)));
        const coeff = dot * edge;
        const col = (255 * coeff) | 0;
        const alpha = (col * coeff * op) | 0;
        const idx = (y1 * c.width + x1) * 4;
        d[idx] = col; d[idx + 1] = col; d[idx + 2] = col; d[idx + 3] = alpha;
      }
    }
    ctx.putImageData(img, 0, 0);
    return c.toDataURL();
  }

  function buildMaps(w, h, radius) {
    const key = w + 'x' + h + 'r' + Math.round(radius);
    let entry = mapCache.get(key);
    if (entry) return entry;
    const r = Math.min(radius, w / 2, h / 2);
    const bezel = Math.max(3, Math.min(r * 0.9, Math.min(w, h) * 0.4, 26));
    const thickness = Math.max(6, Math.min(bezel * 1.6, 40));
    const profile = calculateRefractionProfile(thickness, bezel, 1.5, 96);
    // 实际最大位移量：小元素收敛（避免过度扭曲文字），大圆角适度放宽
    const maxDisp = Math.min(Math.max(r * 0.85, 3), 12);
    entry = {
      url: generateDisplacementCanvas(w, h, r, bezel, profile, maxDisp),
      specUrl: generateSpecularCanvas(w, h, r, bezel)
    };
    if (mapCache.size >= MAP_CACHE_MAX) {
      mapCache.delete(mapCache.keys().next().value);
    }
    mapCache.set(key, entry);
    return entry;
  }

  // ============ SVG 滤镜装配（共享 defs，按 模式x尺寸x圆角 桶复用） ============
  const svgNS = 'http://www.w3.org/2000/svg';
  const xlinkNS = 'http://www.w3.org/1999/xlink';
  let sharedDefs = null;
  const filterBuckets = new Map(); // key -> filterId
  const filterUsers = new Map(); // filterId -> 引用元素数（LG-1 回收依据）

  function ensureSharedDefs() {
    if (sharedDefs && document.body.contains(sharedDefs)) return sharedDefs;
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('width', '0');
    svg.setAttribute('height', '0');
    svg.style.cssText = 'position:absolute;width:0;height:0;pointer-events:none;';
    sharedDefs = document.createElementNS(svgNS, 'defs');
    svg.appendChild(sharedDefs);
    document.body.appendChild(svg);
    return sharedDefs;
  }

  function fe(name, attrs) {
    const node = document.createElementNS(svgNS, name);
    for (const k in attrs) node.setAttribute(k, String(attrs[k]));
    // feImage 的 href 需要 xlink 命名空间别名才能在所有 Chromium 版本稳定生效
    if (attrs.href) node.setAttributeNS(xlinkNS, 'xlink:href', attrs.href);
    return node;
  }

  // 装配滤镜链：SourceGraphic → 微模糊 → （多通道）位移 → 增艳 → 高光合成
  // aberration=true 时 R/G/B 以不同 scale 位移后 screen 混合（边缘色散，中心不受影响——
  // 位移贴图只在边缘环带非零，天然起到 liquid实现3 中 EDGE_MASK 的作用）
  function buildFilterEl(id, w, h, maps, displaceScale, aberration) {
    const filter = fe('filter', { id, x: '-20%', y: '-20%', width: '140%', height: '140%', colorInterpolationFilters: 'sRGB' });
    filter.appendChild(fe('feImage', { href: maps.url, x: 0, y: 0, width: w, height: h, result: 'MAP', preserveAspectRatio: 'none' }));
    filter.appendChild(fe('feGaussianBlur', { in: 'SourceGraphic', stdDeviation: 0.4, result: 'SRC' }));

    const channelMats = {
      CHR: '1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0',
      CHG: '0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0',
      CHB: '0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0'
    };
    let displaced;
    if (aberration) {
      // v3 评估 B1：色散差值 6%/12% → 15%/25%——原差值在强边缘几乎不可见，
      // 拉大后 R/B 边缘出现可辨彩虹边（Apple 色散特征），成本不变（仍 3 次位移）
      const passes = [
        ['DISPR', 'CHR', displaceScale],
        ['DISPG', 'CHG', displaceScale * 0.85],
        ['DISPB', 'CHB', displaceScale * 0.75]
      ];
      passes.forEach(([res, chan, scale]) => {
        filter.appendChild(fe('feDisplacementMap', { in: 'SRC', in2: 'MAP', scale, xChannelSelector: 'R', yChannelSelector: 'G', result: res }));
        filter.appendChild(fe('feColorMatrix', { in: res, type: 'matrix', values: channelMats[chan], result: chan }));
      });
      filter.appendChild(fe('feBlend', { in: 'CHG', in2: 'CHB', mode: 'screen', result: 'GBC' }));
      filter.appendChild(fe('feBlend', { in: 'CHR', in2: 'GBC', mode: 'screen', result: 'RGBJ' }));
      filter.appendChild(fe('feGaussianBlur', { in: 'RGBJ', stdDeviation: 0.35, result: 'SOFT' }));
      displaced = 'SOFT';
    } else {
      filter.appendChild(fe('feDisplacementMap', { in: 'SRC', in2: 'MAP', scale: displaceScale, xChannelSelector: 'R', yChannelSelector: 'G', result: 'DISP' }));
      displaced = 'DISP';
    }

    filter.appendChild(fe('feColorMatrix', { in: displaced, type: 'saturate', values: String(glassSatur), result: 'SAT' }));
    filter.appendChild(fe('feImage', { href: maps.specUrl, x: 0, y: 0, width: w, height: h, result: 'SPEC', preserveAspectRatio: 'none' }));
    // 高光贴图 alpha 作为遮罩，把增艳后的折射内容裁进高光区
    filter.appendChild(fe('feComposite', { in: 'SAT', in2: 'SPEC', operator: 'in', result: 'SMASK' }));
    const specFade = fe('feComponentTransfer', { in: 'SPEC', result: 'SFADE' });
    specFade.appendChild(fe('feFuncA', { type: 'linear', slope: 0.5 }));
    filter.appendChild(specFade);
    filter.appendChild(fe('feBlend', { in: 'SMASK', in2: displaced, mode: 'normal', result: 'WITH' }));
    filter.appendChild(fe('feBlend', { in: 'SFADE', in2: 'WITH', mode: 'normal', result: 'BASE' }));
    if (aberration) {
      // v3 评估 B2：噪点降权（0.06 → 0.02）——噪点是微软 Acrylic 的语汇（MULTIPLY 混合的
      // 颗粒层），Apple 的 clear glass 是干净的，质感来自折射+镜面+色散；保留极弱一层
      // 兼顾大平面上的带通抖动抑制，不删（测试断言 feTurbulence 存在）
      filter.appendChild(fe('feTurbulence', { type: 'fractalNoise', baseFrequency: '0.9', numOctaves: '2', seed: '7', stitchTiles: 'stitch', result: 'NOISE' }));
      filter.appendChild(fe('feColorMatrix', { in: 'NOISE', type: 'matrix', values: '0 0 0 0 0.55  0 0 0 0 0.55  0 0 0 0 0.58  0 0 0 0.02 0', result: 'GRAIN' }));
      filter.appendChild(fe('feBlend', { in: 'GRAIN', in2: 'BASE', mode: 'soft-light' }));
    }
    return filter;
  }

  // 滤镜桶上限（修复实锤5 / LG-1 2026-09-15 v7）：桶随 模式x尺寸x圆角 组合增长。
  // 桶满时先回收「引用计数为 0」的滤镜（元素已 detach 或尺寸变更后遗留的旧桶——
  // 它们的 backdrop-filter 已不再指向这些节点，删除 SVG 节点无副作用），仍满才退磨砂
  // 等待回升。原实现只增不减，撞满 48 后本会话永久退化（LG-1）。
  const FILTER_BUCKETS_MAX = 48;

  function useFilter(id) {
    filterUsers.set(id, (filterUsers.get(id) || 0) + 1);
  }
  function releaseFilter(id) {
    const n = (filterUsers.get(id) || 0) - 1;
    if (n <= 0) filterUsers.delete(id);
    else filterUsers.set(id, n);
  }
  function sweepUnusedFilters() {
    const defs = sharedDefs && document.body.contains(sharedDefs) ? sharedDefs : null;
    let removed = 0;
    for (const [key, id] of [...filterBuckets]) {
      if (filterUsers.has(id)) continue;
      filterBuckets.delete(key);
      if (defs) {
        const node = defs.querySelector('[id="' + id + '"]');
        if (node) node.remove();
      }
      removed++;
    }
    return removed;
  }

  function getFilterId(kind, w, h, radius) {
    const key = kind + '|' + w + 'x' + h + 'r' + Math.round(radius);
    let id = filterBuckets.get(key);
    if (id) return id;
    if (filterBuckets.size >= FILTER_BUCKETS_MAX && sweepUnusedFilters() === 0) return null;
    const maps = buildMaps(w, h, radius);
    id = 'lg-f-' + kind + '-' + Math.random().toString(36).slice(2, 8);
    const filterEl = buildFilterEl(id, w, h, maps, Math.min(Math.max(radius * 0.85, 3), 12), kind === 'full');
    ensureSharedDefs().appendChild(filterEl);
    filterBuckets.set(key, id);
    return id;
  }

  function readRadius(el) {
    const v = parseFloat(getComputedStyle(el).borderTopLeftRadius);
    return Number.isFinite(v) && v > 0 ? v : 4;
  }

  function setBackdrop(el, value) {
    el.style.backdropFilter = value;
    el.style.webkitBackdropFilter = value;
  }

  // ============ 元素玻璃挂载（按钮 / 弹层） ============
  function attachGlass(el) {
    if (glassStates.has(el) || !el.isConnected) return;
    const kind = el.matches(FLOATING_SELECTOR) ? 'floating' : (el.matches(BUTTON_SELECTOR) ? 'button' : 'control');
    const rect = el.getBoundingClientRect();
    const w = Math.round(rect.width), h = Math.round(rect.height);
    if (!w || !h) return; // 隐藏中（未激活页 / 未显示弹窗），后续扫描再挂
    const radius = readRadius(el);
    const overBudget = !withinRefractBudget(w, h, radius);
    const wantRefract = mode !== 'frost' && mode !== 'off' && refractionSupported && !overBudget && refractCount < MAX_REFRACT;
    const blur = kind === 'floating' ? 9 : 2;
    const st = { kind, w, h, radius, blur, refract: false };
    if (wantRefract) {
      const id = getFilterId(mode, w, h, st.radius);
      if (id) {
        st.refract = true;
        st.filterId = id;
        useFilter(id);
        refractCount++;
        setBackdrop(el, `url(#${id}) blur(${blur}px) saturate(${glassSatur}) brightness(${glassBright})`);
      } else {
        // 滤镜桶满（上限护栏）：退化为磨砂，scheduleScan 会在容量腾出后升级
        setBackdrop(el, `blur(${kind === 'floating' ? 18 : blur}px) saturate(${glassSatur}) brightness(${glassBright})`);
      }
    } else {
      // 超预算 / 不支持折射：纯磨砂（弹层面积大，磨砂力度比按钮更高）
      setBackdrop(el, `blur(${kind === 'floating' ? 18 : blur}px) saturate(${glassSatur}) brightness(${glassBright})`);
    }
    glassStates.set(el, st);
    // 全量观察（含磨砂元素）：尺寸变化后可重新评估折射资格（实锤6 资格回升）
    glassRo.observe(el);
    if (kind === 'button') {
      if (mode === 'full' && !reduceMotion) {
        el.classList.add('lg-elastic');
        elasticEls.add(el);
      }
    } else if (kind === 'floating' && mode === 'full') {
      // control（输入控件）不挂 shimmer：弹层点睛属于浮层，输入区不做焦散
      shimmer.attach(el);
    }
  }

  // 折射资格回升（修复实锤6）：元素缩小回预算内 / 折射名额或滤镜桶腾出后，
  // 把停在纯 blur 的元素升回折射。只升不降，降级路径在 glassRo 与 attachGlass
  function tryUpgradeGlass(el, st) {
    if (st.refract || el.isConnected === false) return;
    if (mode !== 'full' && mode !== 'standard') return;
    if (!refractionSupported || refractCount >= MAX_REFRACT) return;
    if (st.w * st.h > MAX_REFRACT_AREA) return;
    if (2 * (st.w + st.h) * ringBezel(st.w, st.h, st.radius) > MAX_RING_PIXELS) return;
    const id = getFilterId(mode, st.w, st.h, st.radius);
    if (!id) return; // 桶满，等下一轮扫描
    st.refract = true;
    st.filterId = id;
    useFilter(id);
    refractCount++;
    setBackdrop(el, `url(#${id}) blur(${st.blur}px) saturate(${glassSatur}) brightness(${glassBright})`);
  }

  function detachGlass(el, st) {
    if (st && st.refract) refractCount = Math.max(0, refractCount - 1);
    if (st && st.filterId) { releaseFilter(st.filterId); st.filterId = null; }
    glassRo.unobserve(el);
    setBackdrop(el, '');
    el.classList.remove('lg-elastic');
    resetElasticVars(el);
    glassStates.delete(el);
  }

  function detachAllGlass() {
    glassStates.forEach((st, el) => {
      if (st.refract) refractCount = Math.max(0, refractCount - 1);
      if (st.filterId) releaseFilter(st.filterId);
      glassRo.unobserve(el);
      setBackdrop(el, '');
      el.classList.remove('lg-elastic');
      resetElasticVars(el);
    });
    glassStates.clear();
    elasticEls.clear();
    shimmer.destroyAll();
    refractCount = 0;
  }

  function attachIfNew(el) {
    if (!el || !el.matches) return;
    if (el.matches(REFRACT_SELECTOR + ',' + FLOATING_SELECTOR)) attachGlass(el);
    // 容器节点：扫描其内部（弹窗整体插入 body 时一次带出全部按钮）
    if (el.querySelectorAll) {
      el.querySelectorAll(REFRACT_SELECTOR + ',' + FLOATING_SELECTOR).forEach(attachGlass);
    }
  }

  // 清理已脱离文档的元素，防止 states 泄漏
  function sweepDetached() {
    glassStates.forEach((st, el) => {
      if (!el.isConnected) detachGlass(el, st);
    });
    elasticEls.forEach((el) => {
      if (!el.isConnected) elasticEls.delete(el);
    });
  }

  const glassRo = new ResizeObserver((entries) => {
    if (mode !== 'full' && mode !== 'standard') return;
    entries.forEach((entry) => {
      const el = entry.target;
      const st = glassStates.get(el);
      if (!st) return;
      const w = Math.round(entry.contentRect.width), h = Math.round(entry.contentRect.height);
      if (w === st.w && h === st.h) return;
      st.w = w; st.h = h;
      if (st.refract) {
        // 尺寸变化：重选桶（滤镜随尺寸重建，位移贴图走缓存）；超预算则降回磨砂
        refractCount = Math.max(0, refractCount - 1);
        st.refract = false;
        if (st.filterId) { releaseFilter(st.filterId); st.filterId = null; }
        if (withinRefractBudget(w, h, st.radius)) {
          const id = getFilterId(mode, w, h, st.radius);
          if (id) {
            st.refract = true;
            st.filterId = id;
            useFilter(id);
            refractCount++;
            setBackdrop(el, `url(#${id}) blur(${st.blur}px) saturate(${glassSatur}) brightness(${glassBright})`);
            return;
          }
        }
        setBackdrop(el, `blur(${st.blur}px) saturate(${glassSatur}) brightness(${glassBright})`);
      } else {
        // 修复实锤6：磨砂元素尺寸变化后重新评估折射资格（缩小回预算内可回升）
        tryUpgradeGlass(el, st);
      }
    });
  });

  // 动态 UI 跟挂：弹窗 / 各页动态渲染的按钮（优化中心分类栏等）延迟出现后补挂
  let scanTimer = 0;
  function scheduleScan() {
    if (scanTimer) return;
    scanTimer = setTimeout(() => {
      scanTimer = 0;
      if (mode !== 'full' && mode !== 'standard') return;
      sweepDetached();
      document.querySelectorAll(REFRACT_SELECTOR + ',' + FLOATING_SELECTOR).forEach((el) => {
        if (!glassStates.has(el)) attachGlass(el);
      });
      // 修复实锤6：折射名额/滤镜桶腾出后，回收此前降级为磨砂的元素
      glassStates.forEach((st, el) => {
        if (el.isConnected) tryUpgradeGlass(el, st);
      });
    }, 120);
  }

  // ============ 指针弹性形变 + 高光跟随（full 模式） ============
  let elasticRaf = 0;
  const pointer = { x: -1e5, y: -1e5 };

  function resetElasticVars(el) {
    el.style.removeProperty('--lg-sx');
    el.style.removeProperty('--lg-sy');
    el.style.removeProperty('--lg-tx');
    el.style.removeProperty('--lg-ty');
    el.style.removeProperty('--lg-press');
  }

  function updateElastics() {
    elasticRaf = 0;
    if (mode !== 'full') return;
    elasticEls.forEach((el) => {
      if (!el.isConnected) { elasticEls.delete(el); return; }
      const r = el.getBoundingClientRect();
      if (!r.width) return;
      const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      const dx = pointer.x - cx, dy = pointer.y - cy;
      const edgeX = Math.max(0, Math.abs(dx) - r.width / 2);
      const edgeY = Math.max(0, Math.abs(dy) - r.height / 2);
      const edge = Math.sqrt(edgeX * edgeX + edgeY * edgeY);
      if (edge > ELASTIC_ZONE) {
        if (el.__lgActive) { resetElasticVars(el); el.__lgActive = false; }
        return;
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
    });
  }

  function onPointerMove(e) {
    pointer.x = e.clientX;
    pointer.y = e.clientY;
    if (elasticRaf) return;
    elasticRaf = requestAnimationFrame(updateElastics);
  }

  // 高光渐变随指针流动（CSS 变量驱动 ::before radial specular 光斑）。
  // 修复实锤4：只往消费方 .lg-elastic 写入——弹层光效由 WebGL shimmer 承担（full 档），
  // 原先对弹层写入 --lg-mx/--lg-my 无任何读取方，属死变量。
  // 值必须带 %：CSS radial-gradient 的 circle at 位置吃 <percentage>，无单位数字会让
  // 整条渐变在 computed-value 阶段非法回退为 none
  function onPointerOver(e) {
    const el = e.target && e.target.closest ? e.target.closest('.lg-elastic') : null;
    if (!el) return;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    el.style.setProperty('--lg-mx', (((e.clientX - r.left) / r.width) * 100).toFixed(1) + '%');
    el.style.setProperty('--lg-my', (((e.clientY - r.top) / r.height) * 100).toFixed(1) + '%');
  }

  function onPressIn(e) {
    const el = e.target && e.target.closest ? e.target.closest('.lg-elastic') : null;
    if (el) el.style.setProperty('--lg-press', '0.96');
  }
  function onPressOut(e) {
    const el = e.target && e.target.closest ? e.target.closest('.lg-elastic') : null;
    if (el) el.style.removeProperty('--lg-press');
  }

  // ============ WebGL 弹层焦散高光（full 模式，弹层点睛） ============
  const shimmer = {
    items: new Map(), // el -> { canvas, gl, glState, raf, ro, last }

    vertSrc: [
      'attribute vec2 aPos;',
      'void main() { gl_Position = vec4(aPos, 0.0, 1.0); }'
    ].join('\n'),

    fragSrc: [
      'precision mediump float;',
      'uniform vec2 uRes;',
      'uniform float uTime;',
      'uniform float uRadius;',
      'float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }',
      'float noise(vec2 p) {',
      '  vec2 ip = floor(p), fp = fract(p);',
      '  vec2 u = fp * fp * (3.0 - 2.0 * fp);',
      '  return mix(mix(hash(ip), hash(ip + vec2(1.0, 0.0)), u.x),',
      '             mix(hash(ip + vec2(0.0, 1.0)), hash(ip + vec2(1.0, 1.0)), u.x), u.y);',
      '}',
      'float fbm(vec2 p) {',
      '  float v = 0.0, a = 0.5;',
      '  for (int i = 0; i < 4; i++) { v += a * noise(p); p *= 2.03; a *= 0.5; }',
      '  return v;',
      '}',
      'void main() {',
      '  vec2 pos = gl_FragCoord.xy;',
      '  vec2 hf = uRes * 0.5;',
      '  vec2 p = pos - hf;',
      '  float r = min(uRadius, min(hf.x, hf.y));',
      '  vec2 q = abs(p) - (hf - r);',
      '  float d = length(max(q, 0.0)) - r;',
      '  float edge = smoothstep(-16.0, 0.0, d);',
      '  float t = uTime * 0.35;',
      '  float n1 = fbm(gl_FragCoord.xy / uRes * 3.0 + vec2(t * 0.6, -t * 0.4));',
      '  float n2 = fbm(gl_FragCoord.xy / uRes * 4.5 - vec2(t * 0.35, t * 0.5));',
      '  float caustic = pow(clamp(1.0 - abs(n1 - n2) * 3.2, 0.0, 1.0), 6.0);',
      '  float glow = caustic * (0.35 + 0.65 * edge) * 0.5 + edge * 0.16;',
      '  gl_FragColor = vec4(vec3(1.0) * glow, clamp(glow, 0.0, 1.0) * 0.85);',
      '}'
    ].join('\n'),

    attach(el) {
      if (this.items.has(el) || reduceMotion) return;
      let gl = null;
      const canvas = document.createElement('canvas');
      canvas.className = 'lg-shimmer-canvas';
      try {
        gl = canvas.getContext('webgl', { alpha: true, premultipliedAlpha: true, antialias: false });
      } catch (e) { gl = null; }
      if (!gl) return;

      const compile = (type, src) => {
        const sh = gl.createShader(type);
        gl.shaderSource(sh, src);
        gl.compileShader(sh);
        return gl.getShaderParameter(sh, gl.COMPILE_STATUS) ? sh : null;
      };
      const vs = compile(gl.VERTEX_SHADER, this.vertSrc);
      const fs = compile(gl.FRAGMENT_SHADER, this.fragSrc);
      const prog = gl.createProgram();
      gl.attachShader(prog, vs);
      gl.attachShader(prog, fs);
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
      gl.useProgram(prog);

      const buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
      const loc = gl.getAttribLocation(prog, 'aPos');
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      const uRes = gl.getUniformLocation(prog, 'uRes');
      const uTime = gl.getUniformLocation(prog, 'uTime');
      const uRadius = gl.getUniformLocation(prog, 'uRadius');
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

      const item = { canvas, gl, prog, uRes, uTime, uRadius, raf: 0, last: 0, dead: false };
      this.items.set(el, item);
      el.insertBefore(canvas, el.firstChild);

      const draw = (now) => {
        if (item.dead || !el.isConnected || mode !== 'full') {
          this.destroy(el);
          return;
        }
        item.raf = requestAnimationFrame(draw);
        // 火眼眼审查 2026-09-14（MED）：后台/失焦时暂停 shimmer 重绘（rAF 先行续排保证
        // 恢复可见后自动续跑），不再空耗 GPU/CPU
        if (document.hidden) return;
        if (now - item.last < 33) return; // ~30fps 足够
        item.last = now;
        const w = canvas.width, h = canvas.height;
        gl.viewport(0, 0, w, h);
        gl.uniform2f(item.uRes, w, h);
        gl.uniform1f(item.uTime, now / 1000);
        gl.uniform1f(item.uRadius, readRadius(el));
        gl.clearColor(0, 0, 0, 0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      };

      const resize = () => {
        if (item.dead) return;
        const r = el.getBoundingClientRect();
        const dpr = Math.min(window.devicePixelRatio || 1, 1.5) * 0.5; // 半分辨率：噪声纹理无需全清
        canvas.width = Math.max(2, Math.round(r.width * dpr));
        canvas.height = Math.max(2, Math.round(r.height * dpr));
      };
      item.ro = new ResizeObserver(resize);
      item.ro.observe(el);
      resize();
      item.raf = requestAnimationFrame(draw);
    },

    destroy(el) {
      const item = this.items.get(el);
      if (!item) return;
      item.dead = true;
      if (item.raf) cancelAnimationFrame(item.raf);
      item.ro?.disconnect();
      item.canvas.remove();
      this.items.delete(el);
    },

    destroyAll() {
      Array.from(this.items.keys()).forEach((el) => this.destroy(el));
    }
  };

  // ============ 分段栏滑块（原有机制，贴图换成物理折射版） ============
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

  // 侧边栏 bar（纵向滑动、小圆角、不开折射贴图——性能护栏见 placeThumb）
  function isSidebarBar(bar) { return bar && bar.id === 'sidebar'; }

  function createThumb(bar, state) {
    const thumb = document.createElement('span');
    thumb.className = 'lg-thumb';
    // v3.2.0：侧边栏滑块挂进 .nav-scroll 滚动容器内——nav 纵向滚动时滑块随内容
    // 自然跟随（.nav-scroll 已 position:relative），免去 scrollTop 逐帧修正
    const mount = isSidebarBar(bar) ? (bar.querySelector('.nav-scroll') || bar) : bar;
    mount.appendChild(thumb);
    state.thumb = thumb;
    return thumb;
  }

  // 每个滑块一个独立滤镜（尺寸随标签变化时重建，位移贴图走缓存）
  function ensureFilter(state, w, h, radius) {
    const needRebuild = !state.filterEl || Math.abs(state.mapW - w) > 1 || Math.abs(state.mapH - h) > 1;
    if (!needRebuild) return;
    if (!state.filterId) state.filterId = 'lg-thumb-' + Math.random().toString(36).slice(2, 9);
    state.mapW = w;
    state.mapH = h;
    const maps = buildMaps(w, h, radius);
    const filterEl = buildFilterEl(state.filterId, w, h, maps, Math.min(Math.max(radius * 0.85, 3), 12), mode === 'full');
    if (state.filterEl) state.filterEl.remove();
    ensureSharedDefs().appendChild(filterEl);
    state.filterEl = filterEl;
  }

  function placeThumb(bar, state, animate) {
    const thumb = state.thumb;
    const tab = findActiveTab(bar);
    if (!thumb || !tab) return;
    const vertical = isSidebarBar(bar);
    const x = tab.offsetLeft;
    const y = tab.offsetTop;
    const w = tab.offsetWidth;
    const h = tab.offsetHeight;
    if (!w || !h) return; // 页面隐藏中，等下次刷新
    // 横向 tab 栏保持胶囊；侧边栏菜单项是小圆角（--radius-medium），非胶囊
    const radius = vertical ? 10 : h / 2;

    // v3.2.1（滑块误挤压修复·方案A）：目标坐标与尺寸与上次完全一致时不加挤压类——
    // 修复「点磁盘清理子分段时 refreshAll(true) 让 #sidebar 玻璃块无意义鼓一下」：
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

    // 性能护栏（AGENTS §7 / 方案三-3）：侧边栏菜单项面积约为横向 tab 两倍，
    // 折射滤镜像素级开销翻倍——侧栏滑块只开普通磨砂（blur+saturate），不开 SVG 折射贴图
    if (!vertical && refractionSupported && (mode === 'full' || mode === 'standard')) {
      ensureFilter(state, Math.round(w), Math.round(h), radius);
      // 质感参数读 token（修复实锤2：原 1.55/1.07 硬编码与 --glass-satur/--glass-bright 漂移）
      const bd = `url(#${state.filterId}) blur(1px) saturate(${glassSatur}) brightness(${glassBright})`;
      thumb.style.backdropFilter = bd;
      thumb.style.webkitBackdropFilter = bd;
    } else if (mode !== 'off') {
      const bd = `blur(12px) saturate(${glassSatur}) brightness(${glassBright})`;
      thumb.style.backdropFilter = bd;
      thumb.style.webkitBackdropFilter = bd;
    }

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
    const state = { thumb: null, moved: false };
    states.set(bar, state);
    bar.classList.add('lg-bar');
    createThumb(bar, state);

    // 维护/快捷指令页会整体重渲染栏内容：滑块被清掉后从原位置滑向新目标，
    // 保留液态跟随感；其余变化静默重定位
    new MutationObserver(() => {
      if (!bar.contains(state.thumb)) {
        createThumb(bar, state);
        if (typeof state.lastX === 'number') {
          state.thumb.classList.add('lg-no-anim');
          state.thumb.style.setProperty('--lg-x', state.lastX + 'px');
          // v3.2.0：侧边栏纵向坐标一并恢复（top=0 + --lg-y），否则重建后瞬跳回顶部
          if (typeof state.lastY === 'number') {
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
    }).observe(bar, { childList: true });

    schedulePlace(bar, false);
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
    states.forEach((state, bar) => {
      if (!state.thumb) return;
      state.thumb.style.display = mode === 'off' ? 'none' : '';
      schedulePlace(bar, animate !== false);
    });
  }

  // ============ 模式切换 ============
  function applyModeClass() {
    const body = document.body;
    MODES.forEach((m) => body.classList.toggle('lg-mode-' + m, mode === m));
  }

  function detectRefractionSupport() {
    try {
      // Chromium 支持 backdrop-filter 引用 SVG 滤镜；不支持的环境自动降级磨砂
      return CSS.supports('backdrop-filter', 'url(#lg-probe)') ||
             CSS.supports('-webkit-backdrop-filter', 'url(#lg-probe)');
    } catch (e) { return false; }
  }

  let attachedMode = null; // 当前已挂折射玻璃的模式（full/standard），跨档切换需重建滤镜链

  function setMode(next, opts) {
    mode = normalizeMode(next);
    // v2.8.0：环境自适应降级走 persist:false——用户存的偏好不被覆盖，环境恢复后自动回弹
    if (!opts || opts.persist !== false) persistMode(mode);
    applyModeClass();

    if (mode === 'off' || mode === 'frost') {
      // off/frost：移除所有 JS 注入滤镜（含折射），交给 CSS（off 无样式、frost 磨砂）
      detachAllGlass();
      attachedMode = null;
    } else {
      // full↔standard 滤镜链不同（色散差异），先清后挂
      if (attachedMode && attachedMode !== mode) detachAllGlass();
      // 不支持折射时滑块/按钮自动退化为磨砂（placeThumb / attachGlass 内处理）
      document.querySelectorAll(REFRACT_SELECTOR + ',' + FLOATING_SELECTOR).forEach(attachGlass);
      attachedMode = mode;
    }
    refreshBars(false);
    scheduleScan();
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
  function readGlassParams() {
    try {
      const cs = getComputedStyle(document.body);
      const s = parseFloat(cs.getPropertyValue('--glass-satur'));
      const b = parseFloat(cs.getPropertyValue('--glass-bright'));
      if (Number.isFinite(s) && s >= 1) glassSatur = s;
      if (Number.isFinite(b) && b >= 1) glassBright = b;
    } catch (e) { /* 读不到用默认值 */ }
  }

  function getMode() { return mode; }

  // ============ 事件接线 ============
  let bodyMo = null;

  // LG-5（2026-09-15）：reduced-motion 实时求值——原实现 init 时读一次固化，
  // 运行中切换系统「减少动态效果」偏好永不生效（与同库 spotlight v4-M1 修复口径一致，
  // 也消掉本文件 934/975/372/605/757 五种读取各管一段的口径分裂）。
  function bindReducePointerListeners(add) {
    if (add) {
      document.addEventListener('pointermove', onPointerMove, { passive: true });
      document.addEventListener('pointerover', onPointerOverSheenSafe, true);
      document.addEventListener('pointerdown', onPressIn, true);
      document.addEventListener('pointerup', onPressOut, true);
      document.addEventListener('pointercancel', onPressOut, true);
    } else {
      document.removeEventListener('pointermove', onPointerMove, { passive: true });
      document.removeEventListener('pointerover', onPointerOverSheenSafe, true);
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
  }

  function init() {
    mode = readStoredMode();
    refractionSupported = detectRefractionSupport();
    reduceMotion = prefersReduceMotion();
    readGlassParams();
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
      const rmMQ = window.matchMedia('(prefers-reduced-motion: reduce)');
      const onRmChange = () => syncReduceMotion();
      if (typeof rmMQ.addEventListener === 'function') rmMQ.addEventListener('change', onRmChange);
      else if (typeof rmMQ.addListener === 'function') rmMQ.addListener(onRmChange);
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
      window.api.appearance.onEnvState((env) => {
        if (!env) return;
        envBattery = !!env.onBattery;
        if (typeof env.transparencyOff === 'boolean') envNoTransparency = env.transparencyOff;
        applyEnv();
      });
    }

    // 点击任意分段标签：栏内 active 切换完成后，滑块带弹簧动画跟随；
    // 点击也可能切换页面/渲染新按钮，顺带调度一次玻璃扫描
    document.addEventListener('click', (e) => {
      const tab = e.target && e.target.closest ? e.target.closest(TAB_SELECTOR) : null;
      if (tab) {
        const bar = tab.closest(BAR_SELECTOR);
        // LG-5：同上，统一读 reduceMotion 状态量
        if (bar && states.has(bar)) schedulePlace(bar, !reduceMotion);
      }
      scheduleScan();
    }, true);

    // LG-5（2026-09-15）：统一走 syncReduceMotion 同一口径——按初始值挂指针监听，
    // 运行中偏好切换由上面的 matchMedia change 监听接管（原静态块读一次即固化）
    document.body.classList.toggle('lg-reduce-motion', reduceMotion);
    bindReducePointerListeners(!reduceMotion);

    // 字体加载完成会改变标签/按钮尺寸，重新对齐
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(() => { refreshBars(false); scheduleScan(); });
    }

    window.addEventListener('resize', () => { refreshBars(false); scheduleScan(); });

    // 动态 UI 跟挂（弹窗 / 动态渲染的按钮）
    bodyMo = new MutationObserver(scheduleScan);
    bodyMo.observe(document.body, { childList: true, subtree: true });

    mountAll();
    if (mode === 'full' || mode === 'standard') {
      document.querySelectorAll(REFRACT_SELECTOR + ',' + FLOATING_SELECTOR).forEach(attachGlass);
      attachedMode = mode;
    }
    states.forEach((state) => {
      if (state.thumb) state.thumb.style.display = mode === 'off' ? 'none' : '';
    });
  }

  // pointerover 需要元素已挂玻璃才有意义，包一层防呆
  function onPointerOverSheenSafe(e) {
    if (mode === 'full') onPointerOver(e);
  }

  window.liquidBar = {
    init, mountAll, refreshAll: refreshBars, setMode, getMode,
    // 2.0 扩展：手动触发扫描（供动态渲染模块调用，可选项）
    rescan: scheduleScan,
    // 诊断：内部状态快照（ refract 计数 / 能力检测 / 滤镜桶 / 环境自适应 ）
    debug: () => ({
      mode, attachedMode, refractionSupported, reduceMotion, refractCount,
      glassStates: glassStates.size, elastic: elasticEls.size,
      buckets: filterBuckets.size, bars: states.size,
      mapCache: mapCache.size,
      env: { battery: envBattery, noTransparency: envNoTransparency, glassSatur, glassBright }
    })
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
