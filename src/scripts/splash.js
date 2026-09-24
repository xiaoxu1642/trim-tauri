// splash.js - 启动页（v2.7.0 新增，v2.7.1 加速编排，参考 hero-preview/index.html 移植）
// 结构：WebGL 流线背景（烟→淡紫偏白，流星→黄白，作者 Matthias Hurrle，Trim 改色版）
//       + 首次进入完整体验（徽章/简介/进度/点击进入），之后每次启动为紧凑模式（Trim+进度，自动进入）；
//       加载完成后背景淡出（主页内容同步渐显），"Trim" 字样以 FLIP 变换平滑落位到标题栏品牌处
//       （PowerPoint「平滑」效果）。
// 进度编排（v2.7.1）：不再纯假进度——app.js 初始化完成会派发 `trim:boot-ready`，
// 进度条到 92% 后停在原地等真实就绪事件，就绪即收尾进入（紧凑模式最快约 0.5s 进主界面）。
// 约束：CSP 禁内联脚本，全部逻辑在此文件；v3.6.2 起开屏动画无视系统 reduced-motion 完整播放；
//       任何异常（目标元素缺失/脚本异常/transitionend 丢失）都有兜底路径保证进入主界面。
(function () {
  'use strict';

  var SEEN_KEY = 'trim_splash_seen';
  var PROGRESS_MS_FIRST = 1600;   // 首次进入：完整体验节奏（徽章 + 简介 + 进度 + 点击进入）
  var PROGRESS_MS_COMPACT = 500;  // 后续启动：仅 Trim + 进度，真实就绪后立刻进入
  var MORPH_MS = 750;             // 落位动画时长（与 CSS transition 一致）
  var PROGRESS_CAP = 0.92;        // 真实就绪前进度上限（诚实进度：92% = 等 app 初始化）
  var BOOT_READY_HARDCAP = 4000;  // 兜底：等不到 trim:boot-ready 也按时进入（不卡死在启动页）
  var MIN_DISPLAY_MS = 450;       // 最短展示时长，避免启动页一闪而过
  var HARD_EXIT_MS = 15000;       // 兜底：无论卡在哪，15s 后强制进入主界面

  var splash = document.getElementById('splash');
  if (!splash) return; // 无启动页结构（结构异常）直接放行主界面

  var canvas = document.getElementById('splash-canvas');
  var trimEl = document.getElementById('splash-trim');
  var badgeEl = document.getElementById('splash-badge');
  var introEl = document.getElementById('splash-intro');
  var progressEl = document.getElementById('splash-progress');
  var progressFill = document.getElementById('splash-progress-fill');
  var progressText = document.getElementById('splash-progress-text');
  var enterBtn = document.getElementById('splash-enter');
  // 落位目标：标题栏品牌文字（index.html .titlebar-title）
  var titleTarget = document.querySelector('.titlebar-title');

  // v3.6.2 产品决策（用户拍板）：开屏动画是 Trim 品牌资产——WebGL 流线背景、入场、FLIP
  // 落位，即使系统关闭「显示动画」（SPI_GETCLIENTAREAANIMATION=0 → prefers-reduced-motion:
  // reduce）也完整播放，不再按系统开关跳过。body.splash-live 标记供 main.css 的
  // reduced-motion 归零规则排除启动页子树（开屏期间主界面渐显也需要），finish() 摘除。
  // 注：v3.6.1 曾因 PRM 下「静态卡死还要手点」直接摘除启动页；现将 CSS 归零规则豁免 +
  // 完整 JS 编排后，入场/进度/FLIP 全链路真实运行，卡死根因不复存在。
  // M3（v3.6.5）N-3：原先此处声明并求值了
  //   var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  // 但 v3.6.2 改为「开屏完整播放」后，全文再无任何读取点（仅注释提及），属死变量。
  // 处理：删除（而非保留作「参考」）——留着会让后来者误以为仍存在 PRM 分支，
  // 从而错误地在别处依赖它。若将来真要按系统偏好降级，请在真正读取它的位置重新引入。
  try { document.body.classList.add('splash-live'); } catch (e) {}

  var state = 'loading'; // loading → done → entered
  var finished = false;
  var bootReady = false;
  var enterScheduled = false;
  // M3（v3.6.5）N-6：isFirstVisit（及其来源 seen）原先声明在文件末尾的「进度编排」区，
  // 却在其上方就被读取（onBootReady、tick）——那些读取点目前都是异步回调，不会真的触发
  // TDZ，但属隐患（将来任何同步路径读取即抛 ReferenceError）。上移到 state 声明区，
  // 保证所有读取点都晚于声明。
  var seen = false;
  try { seen = localStorage.getItem(SEEN_KEY) === '1'; } catch (e) {}
  var isFirstVisit = !seen;
  var hardTimer = setTimeout(finish, HARD_EXIT_MS);
  // 火眼眼审查 2026-09-14（LOW）：启动页是短生命周期节点，window 级监听（boot-ready /
  // canvas resize）须在 finish 摘除节点时同步解绑，否则闭包与 WebGL 画布残留至窗口关闭
  var canvasResizeHandler = null;

  function nowMs() {
    return (window.performance && performance.now) ? performance.now() : Date.now();
  }
  var start = nowMs();

  function markSeen() {
    try { localStorage.setItem(SEEN_KEY, '1'); } catch (e) {}
  }

  // 终点：揭掉启动页、放行标题栏品牌（body:has 选择器按 .finished 放行 .titlebar-title）
  function finish() {
    if (finished) return;
    finished = true;
    clearTimeout(hardTimer);
    // 开屏结束即摘标，主界面恢复 reduced-motion 无动画常态
    try { document.body.classList.remove('splash-live'); } catch (e) {}
    // 火眼眼审查 2026-09-14（LOW）：节点摘除的同时解绑 window 级监听
    try { window.removeEventListener('trim:boot-ready', onBootReady); } catch (e) {}
    try { if (canvasResizeHandler) window.removeEventListener('resize', canvasResizeHandler); } catch (e) {}
    try {
      splash.classList.add('finished');
      if (splash.parentNode) splash.parentNode.removeChild(splash);
    } catch (e) {}
  }

  function showEnterButton() {
    if (!enterBtn) { enterApp(); return; }
    enterBtn.hidden = false;
    requestAnimationFrame(function () {
      enterBtn.style.transition = 'opacity .35s ease';
      enterBtn.style.opacity = '1';
    });
    enterBtn.addEventListener('click', enterApp, { once: true });
  }

  // 紧凑模式自动进入：真实就绪后尽快，但不早于最短展示时长（防一闪而过）
  function scheduleEnter() {
    if (enterScheduled || state === 'entered') return;
    enterScheduled = true;
    var wait = Math.max(0, MIN_DISPLAY_MS - (nowMs() - start));
    setTimeout(enterApp, wait);
  }

  // v2.7.1：app.js 初始化完成派发 `trim:boot-ready`——进度收尾 + 进入编排的真实触发器
  function onBootReady() {
    if (bootReady) return;
    bootReady = true;
    if (progressFill) progressFill.style.width = '100%';
    if (progressText) progressText.textContent = '加载完成';
    if (progressEl) progressEl.setAttribute('aria-valuenow', '100');
    if (state === 'loading') {
      state = 'done';
      if (isFirstVisit) showEnterButton();
      else scheduleEnter();
    } else if (state === 'done' && !isFirstVisit) {
      scheduleEnter();
    }
  }
  window.addEventListener('trim:boot-ready', onBootReady);
  // 兜底：4s 内没等到 boot-ready（如预览模式/异常）也照常进入
  setTimeout(onBootReady, BOOT_READY_HARDCAP);

  function enterApp() {
    if (state === 'entered') return;
    state = 'entered';
    markSeen();

    var fadeEls = [badgeEl, introEl, progressEl, enterBtn];
    fadeEls.forEach(function (el) {
      if (!el) return;
      // 关键：先解除入场动画（splashFadeIn ... both）对 opacity 的持续占用——
      // fill:both 的终帧 opacity:1 优先级高于内联样式，不清掉它下面的 opacity:0
      // 完全不生效（进度条会残留到 FLIP 结束才随节点移除消失，与 trimEl 同坑）
      el.style.animation = 'none';
      el.style.transition = 'opacity .45s ease';
      el.style.opacity = '0';
      el.style.pointerEvents = 'none';
    });
    splash.classList.add('entering'); // 背景层淡出（CSS 过渡）——主页内容同步渐显

    // 目标缺失：直接进入，不做 FLIP（v3.6.2 起不再因 reduceMotion 跳过）
    if (!trimEl || !titleTarget || !trimEl.getBoundingClientRect || !titleTarget.getBoundingClientRect) {
      setTimeout(finish, 500);
      return;
    }

    // FLIP：把启动页大字变换到标题栏品牌的位置与字号（PowerPoint 平滑）
    var from = trimEl.getBoundingClientRect();
    var to = titleTarget.getBoundingClientRect();
    var cs = window.getComputedStyle(titleTarget);
    // 关键：先解除入场动画（animation fill both）对 transform 的持续占用——
    // CSS 动画优先级高于 transition，不移除它 FLIP 的 transform 会被动画终帧覆盖、纹丝不动
    trimEl.style.animation = 'none';
    // 颜色/字距同步目标，落位瞬间与真实品牌无缝衔接（明暗主题均一致）
    trimEl.style.color = cs.color;
    trimEl.style.letterSpacing = cs.letterSpacing || 'normal';

    var dx = (to.left + to.width / 2) - (from.left + from.width / 2);
    var dy = (to.top + to.height / 2) - (from.top + from.height / 2);
    var s = to.width / Math.max(from.width, 1);

    trimEl.style.transition = 'transform ' + (MORPH_MS / 1000) + 's cubic-bezier(.16, 1, .3, 1)';
    trimEl.style.transformOrigin = 'center';
    trimEl.style.willChange = 'transform';
    // 关键②：先强制一次样式重流，让 transition 进入 before-change style；
    // 否则 transition 与 transform 同帧写入会被视为同一次样式变更，过渡直接跳变不生效
    void trimEl.offsetWidth;
    trimEl.style.transform = 'translate(' + dx + 'px, ' + dy + 'px) scale(' + s + ')';

    var landed = false;
    var onLand = function () {
      if (landed) return;
      landed = true;
      finish();
    };
    trimEl.addEventListener('transitionend', function (e) {
      if (e.propertyName === 'transform') onLand();
    }, { once: true });
    setTimeout(onLand, MORPH_MS + 400); // transitionend 兜底
  }

  // ===== WebGL 流线背景（失败自动退回静态渐变，不阻塞进入） =====
  (function initCanvas() {
    if (!canvas) return;
    var gl = null;
    try { gl = canvas.getContext('webgl2'); } catch (e) { gl = null; }
    if (!gl) return;

    var VERT = '#version 300 es\n' +
      'precision highp float;\n' +
      'in vec4 position;\n' +
      'void main(){gl_Position=position;}';

    var FRAG = '#version 300 es\n' +
      '/*********\n' +
      '* made by Matthias Hurrle (@atzedent) — Trim 启动页改色版\n' +
      '*/\n' +
      'precision highp float;\n' +
      'out vec4 O;\n' +
      'uniform vec2 resolution;\n' +
      'uniform float time;\n' +
      '#define FC gl_FragCoord.xy\n' +
      '#define T time\n' +
      '#define R resolution\n' +
      '#define MN min(R.x,R.y)\n' +
      'float rnd(vec2 p) {\n' +
      '  p=fract(p*vec2(12.9898,78.233));\n' +
      '  p+=dot(p,p+34.56);\n' +
      '  return fract(p.x*p.y);\n' +
      '}\n' +
      'float noise(in vec2 p) {\n' +
      '  vec2 i=floor(p), f=fract(p), u=f*f*(3.-2.*f);\n' +
      '  float a=rnd(i), b=rnd(i+vec2(1,0)), c=rnd(i+vec2(0,1)), d=rnd(i+1.);\n' +
      '  return mix(mix(a,b,u.x),mix(c,d,u.x),u.y);\n' +
      '}\n' +
      'float fbm(vec2 p) {\n' +
      '  float t=.0, a=1.; mat2 m=mat2(1.,-.5,.2,1.2);\n' +
      '  for (int i=0; i<5; i++) { t+=a*noise(p); p*=2.*m; a*=.5; }\n' +
      '  return t;\n' +
      '}\n' +
      'float clouds(vec2 p) {\n' +
      '\tfloat d=1., t=.0;\n' +
      '\tfor (float i=.0; i<3.; i++) {\n' +
      '\t\tfloat a=d*fbm(i*10.+p.x*.2+.2*(1.+i)*p.y+d+i*i+p);\n' +
      '\t\tt=mix(t,d,a);\n' +
      '\t\td=a;\n' +
      '\t\tp*=2./(i+1.);\n' +
      '\t}\n' +
      '\treturn t;\n' +
      '}\n' +
      'void main(void) {\n' +
      '\tvec2 uv=(FC-.5*R)/MN,st=uv*vec2(2,1);\n' +
      '\tfloat S=0.;\n' +
      '\tfloat bg=clouds(vec2(st.x+T*.5,-st.y));\n' +
      '\tuv*=1.-.3*(sin(T*.2)*.5+.5);\n' +
      '\tfor (float i=1.; i<12.; i++) {\n' +
      '\t\tuv+=.1*cos(i*vec2(.1+.01*i, .8)+i*i+T*.5+.1*uv.x);\n' +
      '\t\tvec2 p=uv;\n' +
      '\t\tfloat d=length(p);\n' +
      '\t\tS+=1./d;\n' +
      '\t\tfloat b=noise(i+p+bg*1.731);\n' +
      '\t\tS+=b/length(max(p,vec2(b*p.x*.02,p.y)));\n' +
      '\t}\n' +
      '\tvec3 base=mix(vec3(.965,.955,1.),vec3(.72,.66,.93),clamp(bg,0.,1.)*.9);\n' +
      '\tfloat w=clamp(S*.004-.30,0.,1.);\n' +
      '\tO=vec4(mix(base,vec3(1.02,.96,.70),w*.85),1.);\n' +
      '}';

    function compileShader(type, src) {
      var sh = gl.createShader(type);
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        gl.deleteShader(sh);
        return null;
      }
      return sh;
    }
    var vs = compileShader(gl.VERTEX_SHADER, VERT);
    var fs = compileShader(gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return;
    var prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
    gl.useProgram(prog);
    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, 1, -1, -1, 1, 1, 1, -1]), gl.STATIC_DRAW);
    var posLoc = gl.getAttribLocation(prog, 'position');
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);
    var uRes = gl.getUniformLocation(prog, 'resolution');
    var uTime = gl.getUniformLocation(prog, 'time');

    function resize() {
      var dpr = Math.max(1, 0.5 * (window.devicePixelRatio || 1));
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      gl.viewport(0, 0, canvas.width, canvas.height);
    }
    resize();
    window.addEventListener('resize', resize);
    canvasResizeHandler = resize; // 供 finish() 在启动页摘除时解绑（火眼眼审查 LOW）

    function loop(now) {
      gl.clearColor(1, 1, 1, 1);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.useProgram(prog);
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform1f(uTime, now * 1e-3);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      if (!finished) requestAnimationFrame(loop); // 进入后停止渲染，释放 GPU
    }
    requestAnimationFrame(loop);
  })();

  // ===== 进度编排（v2.7.1：真实事件驱动） =====
  // timer 只推进到 92%（诚实进度：剩余的是等 app.js 真实初始化完成）；
  // `trim:boot-ready` 到达即跳 100% 并进入；4s 硬兜底防止卡死在启动页。
  // M3（v3.6.5）N-6：seen / isFirstVisit 已上移到 state 声明区（消除 TDZ 隐患），
  // 此处只保留依赖它的紧凑模式标记。
  if (!isFirstVisit && splash.classList) splash.classList.add('compact'); // 后续启动：仅 Trim + 进度

  var PROGRESS_MS = isFirstVisit ? PROGRESS_MS_FIRST : PROGRESS_MS_COMPACT;

  function tick(now) {
    if (finished || state !== 'loading') return;
    var raw = Math.min(1, ((now || nowMs()) - start) / PROGRESS_MS);
    var t = Math.min(bootReady ? 1 : PROGRESS_CAP, raw);
    var pct = Math.round(t * 100);
    if (progressFill) progressFill.style.width = pct + '%';
    if (progressText) progressText.textContent = '正在加载 ' + pct + '%';
    if (progressEl) progressEl.setAttribute('aria-valuenow', String(pct));
    if (t < 1) {
      requestAnimationFrame(tick);
      return;
    }
    // 进度走满（必然已 boot-ready）：首访展示「点击进入」，紧凑模式直接编排进入
    state = 'done';
    if (isFirstVisit) showEnterButton();
    else scheduleEnter();
  }
  requestAnimationFrame(tick);
})();
