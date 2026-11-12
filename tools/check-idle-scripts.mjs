// check-idle-scripts.mjs —— 延迟加载脚本的 DOMContentLoaded 守卫门禁（审查 v3-M3）
//
// 为什么判红：`IDLE_SCRIPTS` 与 `PAGE_SCRIPTS` 里的脚本由 app.js 在**首帧空闲后**
// 或**进页时**动态注入，届时 DOMContentLoaded 早已发生——顶层注册该事件等于
// init 永不执行，功能静默失效（真实案例：mouse-trail.js 的鼠标拖尾开关点了没反应）。
//
// 正确姿势（与 updater-ui.js 同款）：
//   if (document.readyState === 'loading') {
//     document.addEventListener('DOMContentLoaded', init);
//   } else { init(); }
//
// 判定：脚本若注册了顶层 `DOMContentLoaded` 监听，就必须同文件带
// `document.readyState` 守卫；二者缺一即红。
//
// 断言 2（v3 C 的 P0，2026-10-02）：app.js「// 初始化各模块」启动名单里的模块名，
// 必须是 index.html 已静态加载的脚本 —— 提前 init 会把模块名写进 _initedModules 台账，
// 脚本随后按需注入时 init 永不重跑，页面按钮与 IPC 订阅静默缺失。
//
// 用法：node tools/check-idle-scripts.mjs

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { blankNonCode } from './lib/src-scan.mjs';

const appJs = readFileSync(join(REPO_ROOT, 'src', 'scripts', 'app.js'), 'utf8');

// 从 app.js 现场提取延迟加载清单（新增文件自动纳入，不用回来改本门禁）
function parseScriptList(block) {
  return [...block.matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]);
}

function extractIdle() {
  const m = appJs.match(/const IDLE_SCRIPTS = \[([^\]]*)\]/);
  if (!m) throw new Error('app.js 里找不到 IDLE_SCRIPTS 清单');
  return parseScriptList(m[1]).filter((s) => s.endsWith('.js'));
}

function extractPages() {
  const m = appJs.match(/const PAGE_SCRIPTS = \{([\s\S]*?)\n  \};/);
  if (!m) throw new Error('app.js 里找不到 PAGE_SCRIPTS 清单');
  // 只取脚本路径（块里混有页面 key 等非路径字符串）；T1h-M04：不能再只认 scripts/，
  // vendor/litebox.js 也是运行时注入件，必须进守卫扫描面。
  return parseScriptList(m[1]).filter((s) => s.endsWith('.js'));
}

const files = [...new Set([...extractIdle(), ...extractPages()])];
const strayPageScripts = extractPages().filter((s) => !s.startsWith('scripts/') && !s.startsWith('vendor/'));

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

const parseSelfChecks = [
  ['单引号清单', parseScriptList("['a.js', 'b.js']").join(',') === 'a.js,b.js'],
  ['双引号清单', parseScriptList('["a.js", "b.js"]').join(',') === 'a.js,b.js'],
  ['单双混写清单', parseScriptList(`['a.js', "b.js"]`).join(',') === 'a.js,b.js'],
];
for (const [label, ok] of parseSelfChecks) {
  check(ok, `清单解析判定器自检（${label}）`, ok ? '' : `${label} 未被解析或数量不符`);
}

console.log('=== 延迟加载脚本 DOMContentLoaded 守卫门禁 ===\n');

// 扫描面地板（P0-4）：清单解析成空集时循环 0 次、bad 恒空 ⇒「✓ 0 个延迟加载脚本均带守卫」
// 是空集假绿。0 对象不允许判绿（AGENTS §4.1）。
check(files.length > 0, '延迟/按页加载清单非空（0 个 = 扫描面失效）', `解析得 ${files.length} 个脚本`);
check(
  strayPageScripts.length === 0,
  'PAGE_SCRIPTS 的非 scripts/ 条目已纳入扫描或显式登记（T1h-M04）',
  strayPageScripts.length ? `未登记：${strayPageScripts.join(', ')}` : '仅 scripts/ 与 vendor/',
);

const bad = [];
// T1h-L04：注册点计数地板。此前注册点只有个位数命中，写法一变（或清单解析塌陷）
// 就归零，输出仍是「✓ 均带守卫（或未注册）」。
// 地板 = 现盘基线（node tools/check-idle-scripts.mjs 现算），少于它说明扫描失明而不是代码变干净。
const GUARD_SITE_FLOOR = 6;
let sites = 0;
let guardedSites = 0;
const filesWithSite = new Set();
for (const rel of files) {
  const text = readFileSync(join(REPO_ROOT, 'src', rel.replace(/^src\//, '')), 'utf8');
  // T1h-L04：先剥注释再判（保留字符串——`'DOMContentLoaded'` 本身是字符串字面量）。
  // 抹除是等长的，行号仍对应原文；`\s*` 跨行，注册调用换行也认得出。
  const code = blankNonCode(text, 'js', { keepStrings: true });
  const lines = code.split('\n');
  const re = /addEventListener\(\s*['"]DOMContentLoaded['"]/g;
  let m;
  while ((m = re.exec(code))) {
    const idx = code.slice(0, m.index).split('\n').length - 1;
    sites++;
    filesWithSite.add(rel);
    let guarded = /document\.readyState/.test(lines[idx]); // 单行守卫形态
    const prev = idx > 0 ? lines[idx - 1] : '';
    if (!guarded && /document\.readyState/.test(prev) && /\belse\b/.test(lines[idx])) guarded = true;
    // 向上找所属块的开括号行（右→左扫字符：`}` 计入未进块，`{` 在深度 0 处
    // 即所属块的开括号），开括号行必须含 readyState 守卫
    if (!guarded) {
      let depth = 0;
      outer: for (let i = idx - 1; i >= 0; i--) {
        const l = lines[i];
        for (let j = l.length - 1; j >= 0; j--) {
          const c = l[j];
          if (c === '}') depth++;
          else if (c === '{') {
            if (depth === 0) {
              guarded = /document\.readyState\s*(===?|!==)\s*['"]loading['"]/.test(l);
              break outer;
            }
            depth--;
          }
        }
      }
    }
    const guardWindow = lines.slice(Math.max(0, idx - 8), idx + 6).join('\n');
    const gm = /document\.readyState\s*(===?|!==)\s*['"]loading['"]/.exec(guardWindow);
    const regText = lines.slice(idx, idx + 3).join('\n');
    const cb = /addEventListener\(\s*['"]DOMContentLoaded['"]\s*,\s*([A-Za-z_$][\w$]*)/.exec(regText)?.[1]
      || [...regText.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)]
        .map((x) => x[1])
        .find((n) => n !== 'addEventListener' && n !== 'document' && n !== 'function');
    if (!guarded) {
      bad.push(`${rel}:${idx + 1}`);
      break;
    }
    if (!gm || gm[1] === '!==' || !cb || !new RegExp(`else[\\s\\S]{0,240}\\b${cb}\\s*\\(`).test(guardWindow)) {
      bad.push(`${rel}:${idx + 1}（readyState 守卫必须是 === 'loading' 且 else 支调用同一个回调 ${cb || '?'}()）`);
      break;
    }
    guardedSites++;
  }
}
check(
  sites >= GUARD_SITE_FLOOR,
  `DOMContentLoaded 注册点计数 ≥ ${GUARD_SITE_FLOOR}（少于地板 = 扫描失明，不是代码变干净）`,
  `实到 ${sites} 处：${filesWithSite.size} 个脚本注册 / ${files.length - filesWithSite.size} 个未注册`,
);
check(
  bad.length === 0,
  `${files.length} 个延迟/按页加载脚本均带 readyState 守卫（或未注册 DOMContentLoaded）`,
  bad.length ? `缺守卫 ${JSON.stringify(bad)} —— 注入时 DOMContentLoaded 已过，init 永不执行` : `带守卫 ${guardedSites} 处`,
);

// ---- 断言 2（v3 C 的 P0）：启动期 init 名单必须 ⊆ index.html 静态加载的脚本 ----
// 为什么判红：`initModuleByName(name)` 会**先**把 name 写进 `_initedModules` 台账，再调
// `window[name]?.init?.()`。脚本此刻还没注入 → 记账成功、init 空转，等 ensurePageScripts
// 把脚本加载完，台账已经占用，init 永不重跑。磁盘清理页就是这么变成「按钮全没绑事件、
// IPC 订阅缺失」的（v2 方案的 P0，本轮把 cleanup 两份摘出首屏时必须钉死）。
const html = readFileSync(join(REPO_ROOT, 'src', 'index.html'), 'utf8');
// 正则必须容忍 `<script>` 上的其它属性：2026-10-14 v3 P1-C 给 body 末尾的静态脚本加了
// `defer`，旧写法 `<script src="X"></script>` 当场一个都匹配不上，`staticNames` 退化成空集，
// 断言 2 于是报「1 个标签 + 3 项提前 init」。这属**判据失明**（扫不到语料），不是语义放宽：
// 用 `(?:^|[\s"])` 级的 `\s` 约束保证仍只认真实的 src 属性（`data-src` 之类不算）。
const staticNames = new Set(
  [...html.matchAll(/<script[^>]*\ssrc="([^"]+)"[^>]*><\/script>/g)].map((m) => m[1].split('/').pop()),
);
check(staticNames.size >= 10, 'index.html 静态脚本清单解析非空（过少 = 正则不认标签写法）', `解析得 ${staticNames.size} 个标签`);
// T1h-L03：锚点不能以「首个空行」收尾——在两条 initModuleByName 中间插一个空行属纯格式化，
// 旧正则 `/\/\/ 初始化各模块\n([\s\S]*?)\n\n/` 会把空行之后的条目移出射程，门禁仍绿。
// 改为逐行扫描：空行与注释不结束名单，遇到第一条其它语句才结束。
const START_ANCHOR = '// 初始化各模块\n';
const anchorIdx = appJs.indexOf(START_ANCHOR);
if (anchorIdx < 0) throw new Error('app.js 里找不到「// 初始化各模块」启动名单——锚点变了，请同步本门禁');
const startupInits = [];
for (const line of appJs.slice(anchorIdx + START_ANCHOR.length).split('\n')) {
  const t = line.trim();
  if (!t || t.startsWith('//')) continue;
  const m = /^initModuleByName\('([^']+)'\);$/.exec(t);
  if (!m) break;
  startupInits.push(m[1]);
}
const premature = startupInits.filter((n) => !staticNames.has(`${n}.js`));
// 扫描面地板（P0-4）：锚点失配解析出 0 项时，旧输出「✓ 启动期 init 名单 0 项均已静态加载」
// 是空集假绿。真出现「合法为空」的形态时改本门禁（fail-loud 好过静默）。
check(startupInits.length > 0, '启动期 init 名单解析非空（0 项 = 锚点失配）', `解析得 ${startupInits.length} 项`);
check(
  premature.length === 0,
  `启动期 init 名单 ${startupInits.length} 项均已在 index.html 静态加载（${staticNames.size} 个标签）`,
  premature.length
    ? `提前 init：${JSON.stringify(premature)} —— 脚本尚未注入就写台账，加载后端账已占用、init 永不重跑`
    : startupInits.join(', '),
);

// ---- 断言 3（P3-4 / F3-M01，2026-10-09）：loadScript 失败必须三态、不得占 init 台账 ----
// 为什么判红：loadScript 失败旧实现也 resolve()，ensurePageScripts / scheduleIdleLoads
// 无条件 initModuleOf ⇒ 空 init 把模块名写进 _initedModules，此后即使补载成功
// 也永不再初始化（断网进页 = 该页按钮全无响应且无从自愈）。判据三条：
//   ① onerror 分支不得把 src 计入 _scriptLoaded（失败可重试）；
//   ② ensurePageScripts 必须按加载结果守护 init（`if (ok) initModuleOf(src)`）；
//   ③ scheduleIdleLoads 的 init 必须判加载结果后再执行；
//   ④ scheduleIdleLoads 的 init 必须**按数组序串行**（2026-10-23）：旧形状对 IDLE_SCRIPTS
//      逐条 `.forEach(... .then(init))`，init 的执行序跟的是**完成序**，而清单注释声称
//      「家族内五项的先后就是依赖序」——那条约束从未被强制，外观层晚完成一步，
//      pathbinding 的 init 就读 window.pathbindingAppearance.load() 当场抛
//      （真机 console：`模块 pathbinding 初始化失败`，且台账已占用、整场半初始化）。
//   ⑤ scheduleIdleLoads 的 init 必须发生在 `await p` 之后、loads 不得被 reverse()/sort()
//      重排（P2-17：旧判据只认 token 出现，「init 提前到 await 前 / reverse / sort」
//      三种单行变异全绿）。
function loadScriptViolations(jsText) {
  const out = [];
  const onerr = jsText.match(/s\.onerror\s*=\s*\(\)\s*=>\s*\{([\s\S]*?)\};/);
  if (!onerr) out.push('loadScript 的 onerror 分支没找到（形状变了？同步本门禁）');
  else {
    if (/_scriptLoaded/.test(onerr[1])) out.push('onerror 分支把 src 计入 _scriptLoaded（失败被记账 = 不可重试）');
    if (!/_scriptLoading\.delete\(src\)/.test(onerr[1])) out.push('onerror 分支没有复位 _scriptLoading.delete(src)（失败标记不复位）');
    if (!/resolve\s*\(\s*false\s*\)/.test(onerr[1])) out.push('onerror 分支没有 resolve(false)（失败与成功同形）');
  }
  const eps = jsText.match(/async function ensurePageScripts\(page\)\s*\{([\s\S]*?)\n  \}/);
  if (!eps) out.push('ensurePageScripts 没找到（形状变了？同步本门禁）');
  else if (!/if\s*\(ok\)\s*initModuleOf\(src\)/.test(eps[1])) {
    out.push('ensurePageScripts 未按加载结果守护 init（失败也会占 _initedModules 台账）');
  }
  const idle = jsText.match(/function scheduleIdleLoads\(\)\s*\{([\s\S]*?)\n  \}/);
  if (!idle) out.push('scheduleIdleLoads 没找到（形状变了？同步本门禁）');
  else {
    if (!/if\s*\(ok\)\s*initModuleOf\(src\)/.test(idle[1])) {
      out.push('scheduleIdleLoads 未按加载结果守护 init（失败也会占 _initedModules 台账）');
    }
    if (/IDLE_SCRIPTS\.forEach\(/.test(idle[1]) || !/for\s*\(/.test(idle[1])) {
      out.push('scheduleIdleLoads 的 init 未走数组序（逐条挂 .then = 跟完成序，家族依赖序形同虚设）');
    } else if (!/await\s+p\b/.test(idle[1]) || /\.then\s*\([^)]*initModuleOf/.test(idle[1])) {
      out.push('scheduleIdleLoads 仍是 for + .then(init) 的完成序（T1h-M02：必须 await 串行）');
    } else {
      // P2-17（T1h-M01）：只认 token 出现会被三种单行变异绕过——init 提到 await 之前
      // 会在加载结果未就绪时占台账；reverse()/sort() 会改写数组序，家族依赖序失效。
      const awaitAt = idle[1].search(/await\s+p\b/);
      const initCalls = [...idle[1].matchAll(/initModuleOf\s*\(\s*src\s*\)/g)].map((m) => m.index);
      if (initCalls.length === 0 || initCalls.some((i) => i < awaitAt)) {
        out.push('scheduleIdleLoads 的 init 出现在 await p 之前（加载结果未就绪就占台账）');
      }
      if (/\.\s*(reverse|sort)\s*\(/.test(idle[1])) {
        out.push('scheduleIdleLoads 出现 reverse()/sort()（IDLE_SCRIPTS 数组序被重排，家族依赖序失效）');
      }
    }
  }
  return out;
}
{
  const POSITIVE_CONTROLS = {
    bad: "s.onerror = () => { _scriptLoading.delete(src); _scriptLoaded.add(src); resolve(); };\n" +
      "async function ensurePageScripts(page) {\n    await loadScript(src);\n    initModuleOf(src);\n  }\n" +
      "function scheduleIdleLoads() {\n    IDLE_SCRIPTS.forEach((src) => loadScript(src).then(() => initModuleOf(src)));\n  }\n",
    good: "s.onerror = () => { _scriptLoading.delete(src); resolve(false); };\n" +
      "async function ensurePageScripts(page) {\n    const ok = await loadScript(src);\n    if (ok) initModuleOf(src);\n  }\n" +
      "function scheduleIdleLoads() {\n    const loads = IDLE_SCRIPTS.map((src) => ({ src, p: loadScript(src) }));\n" +
      "    for (const { src, p } of loads) {\n      const ok = await p;\n      if (ok) initModuleOf(src);\n    }\n  }\n",
  };
  const badHits = loadScriptViolations(POSITIVE_CONTROLS.bad);
  const goodHits = loadScriptViolations(POSITIVE_CONTROLS.good);
  check(
    badHits.length === 5 && goodHits.length === 0,
    'loadScript 三态 + 数组序 init 判定器自检（违例 5 条全命中 / 合规样本放行）',
    badHits.length !== 5
      ? `实到 ${badHits.length}：${badHits.join('；')}`
      : goodHits.length
        ? `合规样本被判红：${goodHits.join('；')}`
        : '',
  );
  // P2-17：三条单行变异必须判红——只认 token 的旧判据对它们全绿。
  // 样本只改 scheduleIdleLoads，其余段落保持合规，命中数 > 0 即证明新断言能红。
  const IDLE_MUTATIONS = {
    'init 提前到 await 之前': POSITIVE_CONTROLS.good.replace(
      '      const ok = await p;\n      if (ok) initModuleOf(src);',
      '      let ok = true;\n      if (ok) initModuleOf(src);\n      ok = await p;',
    ),
    'loads.reverse()': POSITIVE_CONTROLS.good.replace(
      '    for (const { src, p } of loads) {',
      '    loads.reverse();\n    for (const { src, p } of loads) {',
    ),
    'loads.sort()': POSITIVE_CONTROLS.good.replace(
      '    for (const { src, p } of loads) {',
      '    loads.sort();\n    for (const { src, p } of loads) {',
    ),
  };
  for (const [label, sample] of Object.entries(IDLE_MUTATIONS)) {
    const hits = loadScriptViolations(sample);
    check(hits.length > 0, `loadScript 数组序变异自检（${label} ⇒ 判红）`, hits.join('；'));
  }
  const real = loadScriptViolations(appJs);
  check(
    real.length === 0,
    'loadScript 失败不占 init 台账（三态 + 两处 init 守卫）',
    real.join('；'),
  );
}

console.log('');
if (fail > 0) {
  console.error('门禁失败：有断言未通过');
  process.exit(1);
}
console.log('延迟加载脚本门禁全部通过');
