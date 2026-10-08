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

const appJs = readFileSync(join(REPO_ROOT, 'src', 'scripts', 'app.js'), 'utf8');

// 从 app.js 现场提取延迟加载清单（新增文件自动纳入，不用回来改本门禁）
function extractIdle() {
  const m = appJs.match(/const IDLE_SCRIPTS = \[([^\]]*)\]/);
  if (!m) throw new Error('app.js 里找不到 IDLE_SCRIPTS 清单');
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
}

function extractPages() {
  const m = appJs.match(/const PAGE_SCRIPTS = \{([\s\S]*?)\n  \};/);
  if (!m) throw new Error('app.js 里找不到 PAGE_SCRIPTS 清单');
  // 只取脚本路径（块里混有页面 key 等非路径字符串）
  return [...m[1].matchAll(/'([^']+)'/g)]
    .map((x) => x[1])
    .filter((s) => s.startsWith('scripts/') && s.endsWith('.js'));
}

const files = [...new Set([...extractIdle(), ...extractPages()])];

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 延迟加载脚本 DOMContentLoaded 守卫门禁 ===\n');

// 扫描面地板（P0-4）：清单解析成空集时循环 0 次、bad 恒空 ⇒「✓ 0 个延迟加载脚本均带守卫」
// 是空集假绿。0 对象不允许判绿（AGENTS §4.1）。
check(files.length > 0, '延迟/按页加载清单非空（0 个 = 扫描面失效）', `解析得 ${files.length} 个脚本`);

const bad = [];
for (const rel of files) {
  const text = readFileSync(join(REPO_ROOT, 'src', rel.replace(/^src\//, '')), 'utf8');
  const lines = text.split('\n');
  // 结构判定：注册点必须 ① 在含 readyState 的 if 块内（花括号深度 > 0 且向上
  // 能找到守卫 if 行），或 ② 该行自带 readyState，或 ③ 紧随 readyState 行的 else。
  // 其余（顶层裸注册）= M3 的静默失效形态，红。
  const re = /addEventListener\(\s*['"]DOMContentLoaded['"]/;
  for (let idx = 0; idx < lines.length; idx++) {
    if (!re.test(lines[idx])) continue;
    if (/document\.readyState/.test(lines[idx])) continue; // 单行守卫形态
    const prev = idx > 0 ? lines[idx - 1] : '';
    if (/document\.readyState/.test(prev) && /\belse\b/.test(lines[idx])) continue;
    // 向上找所属块的开括号行（右→左扫字符：`}` 计入未进块，`{` 在深度 0 处
    // 即所属块的开括号），开括号行必须含 readyState 守卫
    let depth = 0;
    let guarded = false;
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
    if (!guarded) {
      bad.push(`${rel}:${idx + 1}`);
      break;
    }
  }
}
check(
  bad.length === 0,
  `${files.length} 个延迟/按页加载脚本均带 readyState 守卫（或未注册 DOMContentLoaded）`,
  bad.length ? `缺守卫 ${JSON.stringify(bad)} —— 注入时 DOMContentLoaded 已过，init 永不执行` : '',
);

// ---- 断言 2（v3 C 的 P0）：启动期 init 名单必须 ⊆ index.html 静态加载的脚本 ----
// 为什么判红：`initModuleByName(name)` 会**先**把 name 写进 `_initedModules` 台账，再调
// `window[name]?.init?.()`。脚本此刻还没注入 → 记账成功、init 空转，等 ensurePageScripts
// 把脚本加载完，台账已经占用，init 永不重跑。磁盘清理页就是这么变成「按钮全没绑事件、
// IPC 订阅缺失」的（v2 方案的 P0，本轮把 cleanup 两份摘出首屏时必须钉死）。
const html = readFileSync(join(REPO_ROOT, 'src', 'index.html'), 'utf8');
const staticNames = new Set(
  [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1].split('/').pop()),
);
const startupBlock = appJs.match(/\/\/ 初始化各模块\n([\s\S]*?)\n\n/);
if (!startupBlock) throw new Error('app.js 里找不到「// 初始化各模块」启动名单——锚点变了，请同步本门禁');
const startupInits = [...startupBlock[1].matchAll(/initModuleByName\('([^']+)'\);/g)].map((m) => m[1]);
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
//   ③ scheduleIdleLoads 的 .then 必须判 ok 后再 init。
function loadScriptViolations(jsText) {
  const out = [];
  const onerr = jsText.match(/s\.onerror\s*=\s*\(\)\s*=>\s*\{([\s\S]*?)\};/);
  if (!onerr) out.push('loadScript 的 onerror 分支没找到（形状变了？同步本门禁）');
  else if (/_scriptLoaded/.test(onerr[1])) out.push('onerror 分支把 src 计入 _scriptLoaded（失败被记账 = 不可重试）');
  const eps = jsText.match(/async function ensurePageScripts\(page\)\s*\{([\s\S]*?)\n  \}/);
  if (!eps) out.push('ensurePageScripts 没找到（形状变了？同步本门禁）');
  else if (!/if\s*\(ok\)\s*initModuleOf\(src\)/.test(eps[1])) {
    out.push('ensurePageScripts 未按加载结果守护 init（失败也会占 _initedModules 台账）');
  }
  const idle = jsText.match(/function scheduleIdleLoads\(\)\s*\{([\s\S]*?)\n  \}/);
  if (!idle) out.push('scheduleIdleLoads 没找到（形状变了？同步本门禁）');
  else if (!/then\(\(ok\)\s*=>/.test(idle[1])) out.push('scheduleIdleLoads 的 .then 未判加载结果');
  return out;
}
{
  const POSITIVE_CONTROLS = {
    bad: "s.onerror = () => { _scriptLoading.delete(src); _scriptLoaded.add(src); resolve(); };\n" +
      "async function ensurePageScripts(page) {\n    await loadScript(src);\n    initModuleOf(src);\n  }\n" +
      "function scheduleIdleLoads() {\n    loadScript(src).then(() => initModuleOf(src));\n  }\n",
    good: "s.onerror = () => { _scriptLoading.delete(src); resolve(false); };\n" +
      "async function ensurePageScripts(page) {\n    const ok = await loadScript(src);\n    if (ok) initModuleOf(src);\n  }\n" +
      "function scheduleIdleLoads() {\n    loadScript(src).then((ok) => { if (ok) initModuleOf(src); });\n  }\n",
  };
  check(
    loadScriptViolations(POSITIVE_CONTROLS.bad).length === 3 && loadScriptViolations(POSITIVE_CONTROLS.good).length === 0,
    'loadScript 三态判定器自检（违例 3 条全命中 / 合规样本放行）',
  );
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
