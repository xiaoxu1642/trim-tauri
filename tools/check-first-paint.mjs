#!/usr/bin/env node
// check-first-paint.mjs —— 首屏关键路径预算 + parser-blocking 不变量（性能审计 v3 P2-I）
//
// 为什么需要它（v3 §8.4 的实测缺口）：首屏 686 KB 此前**完全没有门禁看守**。
// `check-asset-size` 管的是「单个文件是否 >1 MiB」与「src/ 总量」，首屏清单怎么排、
// 有多少是 parser-blocking、有没有偷偷变胖，一律无人问 —— 于是「多挂一个首屏脚本」
// 这种回归只能靠发版前人肉发现。而首屏是双击到窗口出现这条用户可感知路径上最确定的一段：
// 黑闪握手等的是 DOMContentLoaded，而 DCL 要等所有非 defer 静态脚本下载+编译+执行完。
//
// 四组断言：
//   F1 首屏关键路径字节预算（**双向棘轮**：超上限红；跌破下限也红 —— 后者挡的是
//      「为了躲预算偷偷把真实脚本摘出首屏」，那会把按需链变长，不是省了成本）。
//   F2 body 末尾的静态 <script> 必须带 defer；唯一豁免是 EXEMPT_NOT_DEFER 里点名的
//      head 主题引导脚本（它必须早于首次绘制，加了 defer 反而会闪一帧默认主题）。
//   F3 解析面地板：静态 script / stylesheet 条数过少 = 正则不认标签写法 = 判据失明。
//      （这一条的来历：v3 P1-C 给脚本加 defer 后，check-idle-scripts 的
//       `<script src="X"></script>` 精确匹配当场退化到「解析得 1 个标签」而几乎判绿。）
//   F4 首屏 ⇄ 按需清单不得重叠：同一文件既在 index.html 静态挂载、又在 PAGE_SCRIPTS /
//      IDLE_SCRIPTS 里按页注入 = 要么白挂一份字节，要么摘了却没摘净。
//
// 正向对照：判定器都是纯函数，selfCheck() 用合成样本双向验（违例必红、合规必放行），
// 按 AGENTS §4.1「无对照的恒绿断言视同没写」。
//
// 用法：node tools/check-first-paint.mjs
'use strict';
import { readFileSync, statSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT } from './ps-origin.mjs';
import { gate } from './lib/gate.mjs';
import { scriptSrcs, styleLinks } from './lib/html-tags.mjs';

const SRC = join(REPO_ROOT, 'src');
const HTML = join(SRC, 'index.html');
const APP_JS = join(SRC, 'scripts', 'app.js');

// ---- 预算（现算于 2026-10-15，v5 P1 编辑器 + P2 四项落地后）----
// 沿革：v5 P0 增补 9 条 syspanel 桥接后为 701,385 B，上限 702,000 B（贴值留余）。
// 沿革：2026-10-22 系统信息弹窗加「远程调试 (CDP)」一行（index.html 一行 + main.css 一条
//   + app.js 三态函数 + tauri-api.js 两条通道），实测 729,250 B ⇒ 上限 725,000 → 730,000。
// v5 P1 编辑器按 P0 交接文档预告明确重审（702,000 → 710,000）：主增量是 main-pages.css
// 的编辑器面板样式（数千字节量级，已并入既有文件并压缩）。
// v5 P2 同日第三笔（710,000 → 712,000 → 712,500）：用户点名的四项功能（搜索框 / 各方案
// 对照块 / 注册表定位按钮 / 折叠 hidden 兜底修复）都必须落进 main-pages.css——它随首屏
// 静态加载。此前已把注释与小规则压到极限（711,974 = 只余 26 B），继续压缩会伤样式表
// 可读性；按同一「贴值留余」口径留 ~500 B 呼吸位。三次调整全部是审过的功能增量。
// v5 P2 同日收口（712,500 → 713,000）：优化中心「点名称进详情」交互 + modal 的 Esc
// 顶层化修复（modal.js 随首屏静态加载）追加；已先把新加注释压到最短，留 ~500 B 呼吸位。
// 同日第五笔（713,000 → 715,000）：D-01「改动位置透出」+ 账外核对入口/弹窗（含首屏按钮）
// 与弹窗样式追加，压缩后仍超 1161 B。**结构性建议（写在这里防遗忘）**：main-pages.css 已
// 是「按需页样式全量随首屏加载」；继续追加时优先考虑把按需页样式按页拆分、进按需清单，
// 而非反复重审本预算。下限按 CAP_MIN 走：CSS 侧还会因死规则清理继续合法收缩，这里只防
// 「首屏大面积塌陷」。
// G-04（2026-10-16）：开启卓越性能 / 隐藏高性能 / 还原 三条能力的 CHANNEL_MAP 条目与
// api 包装落在 tauri-api.js（首屏静态，+635 B）—— 715,000 → 716,000（贴值留余 ~400 B）。
// 功能面 UI（syspanel.js 三个处理器与按钮）走 PAGE_SCRIPTS['windows-settings'] 按需注入，
// 不在本预算内。
// C1-1（2026-10-16 晚）：占用查询页（index.html 第 5 tab + 面板，+2109 B；app.js +121 B）
// —— 716,000 → 718,500（贴值留余 ~300 B）。该增量为拍板过的功能面（主窗内嵌占用查询），
// 由 P1-7 批次补跑全量门禁时抓出（C1-1 当时只跑了受触面，属「批间不跑全量」的又一笔账）。
// 电源工具组移位（2026-10-16，用户目检点名）：G-04 三按钮从卡片体移到头部「新建电源计划 /
// 刷新」之间——index.html +221 B、main.css +600 B、main-pages.css −40 B（净 +781 B）——
// 718,500 → 719,500（贴值留余 ~520 B）。
// 结构性建议（沿革旧注延续）：main.css / main-pages.css 的「按需页样式全量随首屏」问题仍在——
// 继续追加时优先考虑按页拆样式进按需清单，而非反复上调本预算。
// P0-7（2026-10-18，v6-K14/K17）：速率真源 ds.fmtRate + fmtBytes opts（ds.js 首屏静态）
// 与材质无档 tooltip floor（main.css 首屏静态）——719,500 → 720,500（贴值留余 ~520 B）。
// 两者都是审过的方案项（P0-7），且 ds.js 旧注释已按事实重写（cleanup/finder 早已是薄封装，
// 此前注释称其「保留独立实现」是陈述过时），净增仍 ~490 B。
// v7.2 P0/P1（2026-10-21）：错误态/降级回执 UI（.empty-state--error 等，P0-C06）各约两千字节量级，
// U-A3 可达性（aria-live 宿主 / 焦点环 / 灯箱 alt+caption）约一千五百字节量级——合计 724,117 B。
// 720,500 → 725,000（贴值留余 ~880 B）。两项都经过 review；结构性建议不变：
// main-pages.css 仍全量随首屏，后续新增应优先按页拆进按需清单，而非反复上调。
// 2026-10-22（目检整改批）：软件卸载页等待条改「计时 + 可收起」（index.html 结构 +560 B、
// main.css 新规则 +780 B）与开屏行高 + splash 注释——730,000 → 731,500（实际 731,040 B）。
// 同一天的 app:open-doc 批再加 tauri-api.js 通道与方法（+230 B）、main.css 的 .mw-doc-link
// 按钮化清 UA 盒模型（+150 B）——731,500 → 732,000（实际 731,639 B，留余 ~360 B）。
// 这是**连续第三次**撞顶，且第三次的增长全落在「子窗专用样式也住在 main.css 里」这个
// 已知结构问题上（models-window.html 直接挂整份 main.css）。下一条往 main.css 加规则的
// 批次必须先做按页拆样式进按需清单，不再上调本预算。
// B3/P1-7（2026-10-25）：给 fontmanager.js 的「应用」按钮补 reject 出口需要 +167 B，而当时
// 实测余量只有 **14 B**。预算未上调 —— 该文件先删掉一段讲「MiSans 死分支已删」的历史叙述
// （讲过去改了什么、不约束将来，AGENTS §3 明令注释只写 why/约束），改动自我消化后实测
// 731,928 B，余 72 B。**这条余量已经不容下一次追加**：往首屏 12 个脚本或 4 份 CSS 里再加
// 任何内容之前，先做上面那句结构性建议（按页拆进按需清单），别再来改这个数字。
const CAP_MAX = 732_000;
const CAP_MIN = 400_000;
// 豁免清单：允许不带 defer 的脚本（必须尽早执行，加 defer 反而破坏语义）
const EXEMPT_NOT_DEFER = ['scripts/theme-boot.js'];

const g = gate(import.meta.url);

// ---------- 纯判定器（可被 selfCheck 用合成样本喂） ----------

/** F2：列出「不在豁免清单里、又没带 defer」的脚本 */
export function judgeNotDeferred(scripts, exempt) {
  return scripts.filter((s) => !s.defer && !exempt.includes(s.rel)).map((s) => s.rel);
}
/** F1：预算双向判定 */
export function judgeBudget(total, max, min) {
  const bad = [];
  if (total > max) bad.push(`超上限 ${max} B（实际 ${total} B）`);
  if (total < min) bad.push(`跌破下限 ${min} B（实际 ${total} B）——首屏资源大面积消失，先查是不是把真实脚本摘了躲预算`);
  return bad;
}
/** F4：首屏静态清单 ∩ 按需清单 */
export function judgeOverlap(staticRels, onDemand) {
  const set = new Set(staticRels);
  return [...onDemand].filter((r) => set.has(r));
}
/** F5：首帧握手唯一性（F3-M08）。入参为**剥过注释**的 tauri-api.js 与 app.js 源码。
 *  规则：① notifyFirstPaint() 的调用有且只有 1 处（守卫曾把症状盖住——后端只认首个
 *  通知，但白名单/审计看到的是「一次握手发了两回」）；② 幂等守卫必须与 notifyFirstPaint
 *  **同作用域**（本件整体包在 IIFE 里，「模块作用域」= IIFE 体内，文件深度恒非 0；
 *  `var sent` 缩进函数体内 = 每次 call 一份新标志，假幂等）；③ app.js 不得再有调用点。 */
export function judgeFirstPaintHandshake(apiCode, appCode) {
  const bad = [];
  const depthAt = (code, idx) => {
    let d = 0;
    for (let i = 0; i < idx; i++) {
      const c = code[i];
      if (c === '{' || c === '(' || c === '[') d++;
      else if (c === '}' || c === ')' || c === ']') d--;
    }
    return d;
  };
  const invocations = [...apiCode.matchAll(/notifyFirstPaint\s*\(\s*\)\s*;/g)].length;
  if (invocations !== 1) bad.push(`tauri-api.js 里 notifyFirstPaint() 调用 ${invocations} 处 ≠ 1`);
  const fnDecl = apiCode.match(/function\s+notifyFirstPaint\s*\(/);
  if (!fnDecl) bad.push('tauri-api.js 里找不到 notifyFirstPaint 定义');
  const decl = apiCode.match(/var\s+firstPaintSent\b/);
  if (!decl) {
    bad.push('tauri-api.js 里找不到 firstPaintSent 守卫声明');
  } else if (fnDecl && depthAt(apiCode, decl.index) !== depthAt(apiCode, fnDecl.index)) {
    bad.push(`firstPaintSent 守卫（深度 ${depthAt(apiCode, decl.index)}）与 notifyFirstPaint 定义（深度 ${depthAt(apiCode, fnDecl.index)}）不同作用域 —— 守卫缩进函数体内 = 每次 call 一份新标志，假幂等`);
  }
  // app.js 侧判「出现即违例」：剥注释后任何形态（直接调用、`?.()` 可选链、别名引用）
  // 都算残留触发点，不给调用写法留缝（2026-10-21 破坏验证实测 `?.()` 漏判后收紧）
  const appCalls = [...appCode.matchAll(/notifyFirstPaint\b/g)].length;
  if (appCalls > 0) bad.push(`app.js 里仍有 ${appCalls} 处 notifyFirstPaint 引用（只许 tauri-api.js 末尾发一次）`);
  return bad;
}

// ---------- 解析 ----------
function parseHtml() {
  const html = readFileSync(HTML, 'utf8');
  const scripts = [];
  for (const s of scriptSrcs(html)) {
    const rel = s.src.replace(/^(\.\.\/|\.\/|\/)+/, '').replace(/^src\//, '');
    scripts.push({
      rel,
      defer: s.defer,
      size: existsSync(join(SRC, rel)) ? statSync(join(SRC, rel)).size : -1,
    });
  }
  const css = [];
  for (const href of styleLinks(html)) {
    const rel = href.replace(/^(\.\.\/|\.\/|\/)+/, '').replace(/^src\//, '');
    css.push({ rel, size: existsSync(join(SRC, rel)) ? statSync(join(SRC, rel)).size : -1 });
  }
  return { scripts, css, htmlSize: statSync(HTML).size };
}

/** app.js 的 PAGE_SCRIPTS + IDLE_SCRIPTS 清单（现场提取，不手抄） */
function parseOnDemand() {
  const js = readFileSync(APP_JS, 'utf8');
  const out = new Set();
  const grab = (blockName) => {
    const at = js.indexOf(blockName);
    if (at < 0) return false;
    let d = 0, end = -1;
    for (let i = js.indexOf('{', at); i < js.length; i++) {
      const c = js[i];
      if (c === '{') d++;
      else if (c === '}') { d--; if (d === 0) { end = i; break; } }
    }
    if (end < 0) return false;
    for (const m of js.slice(at, end).matchAll(/['"`]([\w./-]+\.js)['"`]/g)) out.add(m[1]);
    return true;
  };
  const okPage = grab('PAGE_SCRIPTS');
  const okIdle = grab('IDLE_SCRIPTS');
  return { set: out, okPage, okIdle };
}

// ---------- 正向对照自检（违例必红 / 合规必放行） ----------
function selfCheck() {
  const problems = [];
  let groups = 0;
  const expect = (label, got, want) => {
    groups++;
    const ok = Array.isArray(want) ? JSON.stringify(got) === JSON.stringify(want) : Boolean(got) === Boolean(want);
    if (!ok) problems.push(`${label}：得 ${JSON.stringify(got)}，应 ${JSON.stringify(want)}`);
  };
  // F2 反向：未 defer 且不在豁免 → 必须被抓到
  expect(
    'F2 违例样本未命中',
    judgeNotDeferred([{ rel: 'scripts/x.js', defer: false }, { rel: 'scripts/y.js', defer: true }], EXEMPT_NOT_DEFER),
    ['scripts/x.js'],
  );
  // F2 正向：全 defer + 豁免项 → 必须放行（防判据退化成「永远红」）
  expect(
    'F2 合规样本误报',
    judgeNotDeferred([{ rel: 'scripts/y.js', defer: true }, { rel: 'scripts/theme-boot.js', defer: false }], EXEMPT_NOT_DEFER),
    [],
  );
  // F1 双向
  expect('F1 超上限未命中', judgeBudget(CAP_MAX + 1, CAP_MAX, CAP_MIN).length > 0, true);
  expect('F1 跌破下限未命中', judgeBudget(CAP_MIN - 1, CAP_MAX, CAP_MIN).length > 0, true);
  expect('F1 干净样本误报', judgeBudget(CAP_MIN + 1000, CAP_MAX, CAP_MIN), []);
  // F4
  expect('F4 重叠未命中', judgeOverlap(['scripts/a.js'], new Set(['scripts/a.js'])), ['scripts/a.js']);
  expect('F4 无重叠误报', judgeOverlap(['scripts/a.js'], new Set(['scripts/b.js'])), []);
  // F5（F3-M08）：合规样本 + 三种违例形态
  const okApi =
    'var firstPaintSent = false; function notifyFirstPaint() { if (firstPaintSent) return; firstPaintSent = true; } notifyFirstPaint();';
  expect('F5 合规样本误报', judgeFirstPaintHandshake(okApi, ''), []);
  expect(
    'F5 双调用未命中',
    judgeFirstPaintHandshake('var firstPaintSent = false; function notifyFirstPaint() {} notifyFirstPaint(); notifyFirstPaint();', '').length > 0,
    true,
  );
  expect(
    'F5 守卫缩回函数体内（假幂等）未命中',
    judgeFirstPaintHandshake('function notifyFirstPaint() { var firstPaintSent = false; if (firstPaintSent) return; firstPaintSent = true; } notifyFirstPaint();', '').length > 0,
    true,
  );
  expect('F5 app.js 残留调用未命中', judgeFirstPaintHandshake(okApi, 'notifyFirstPaint();').length > 0, true);

  if (problems.length) {
    g.fail(`正向对照自检失效（本门禁的断言不可信）：\n  ${problems.join('\n  ')}`);
    g.finish();
    process.exit(1);
  }
  return { problems, groups };
}

console.log('=== 首屏关键路径门禁 ===\n');

if (!g.skipUnlessPresent(HTML, 'src/index.html')) {
  console.warn('⚠ 输入缺失：F1–F4 全部**未校验**（SKIP，不是通过）');
  g.finish();
  process.exit(0);
}
const { groups: selfGroups } = selfCheck();
g.ok(`正向对照自检 ${selfGroups} 组全部命中（F2 违例必红 + 合规必放行、F1 超上限 + 跌破下限 + 干净放行、F4 重叠必红 + 无重叠放行、F5 合规放行 + 双调用/假幂等/残留调用必红）`);

const { scripts, css, htmlSize } = parseHtml();

// F3 解析面地板
g.ok(`F3 解析面：静态 script ${scripts.length} 条 / stylesheet ${css.length} 条`);
if (scripts.length < 10) {
  g.fail(`F3 静态 script 标签解析数 ${scripts.length} < 10 —— 正则不认标签写法即判据失明（defer/属性顺序都会影响匹配）`);
}
if (css.length < 3) {
  g.fail(`F3 stylesheet 解析数 ${css.length} < 3 —— 主窗至少应挂 main/main-pages/ds 三份`);
}
const missing = [...scripts.filter((s) => s.size < 0), ...css.filter((c) => c.size < 0)].map((x) => x.rel);
if (missing.length) g.fail(`首屏清单里存在定位不到的资源：${JSON.stringify(missing)}（路径写了但文件不在 = 404 级隐患）`);

// F1 预算
const total = htmlSize + scripts.reduce((s, x) => s + Math.max(0, x.size), 0) + css.reduce((s, x) => s + Math.max(0, x.size), 0);
const budgetBad = judgeBudget(total, CAP_MAX, CAP_MIN);
if (budgetBad.length) g.fail(`F1 首屏关键路径 ${total} B —— ${budgetBad.join('；')}`);
else g.ok(`F1 首屏关键路径 ${total} B ≤ 上限 ${CAP_MAX} B（index.html ${htmlSize} + ${scripts.length} 脚本 ${total - htmlSize - css.reduce((s, x) => s + Math.max(0, x.size), 0)} + ${css.length} CSS ${css.reduce((s, x) => s + Math.max(0, x.size), 0)}）`);

// F2 不变量
const notDef = judgeNotDeferred(scripts, EXEMPT_NOT_DEFER);
if (notDef.length) g.fail(`F2 有 ${notDef.length} 条静态脚本未加 defer（parser-blocking，全部落在「双击→窗口出现」路径上）：${JSON.stringify(notDef)}`);
else g.ok(`F2 静态脚本除豁免的 ${EXEMPT_NOT_DEFER.join(', ')} 外全部带 defer（豁免理由：必须早于首次绘制挂主题类）`);

// T1d-L01：子窗 HTML 的 head 内脚本同样不许 parser-blocking（body 末尾脚本不受此限）。
for (const f of readdirSync(SRC).filter((n) => n.endsWith('.html'))) {
  const html = readFileSync(join(SRC, f), 'utf8');
  const head = html.split(/<\/head>/i)[0] || '';
  const bad = scriptSrcs(head)
    .map((s) => ({ rel: s.src.split('/').pop(), defer: s.defer }))
    .filter((s) => !s.defer && !EXEMPT_NOT_DEFER.includes(`scripts/${s.rel}`))
    .map((s) => s.rel);
  if (bad.length) g.fail(`F2b ${f} 的 head 内脚本未加 defer：${JSON.stringify(bad)}`);
}

// F4 首屏 ∩ 按需
const od = parseOnDemand();
if (!od.okPage || !od.okIdle) {
  g.fail(`F4 无法在 app.js 里定位 ${od.okPage ? '' : 'PAGE_SCRIPTS '}${od.okIdle ? '' : 'IDLE_SCRIPTS'}—— 锚点变了，请同步本门禁（不许删本断言）`);
} else {
  const dup = judgeOverlap(scripts.map((s) => s.rel), od.set);
  if (dup.length) g.fail(`F4 ${dup.length} 个脚本既在 index.html 静态挂载、又在按需清单里（白挂字节或没摘净）：${JSON.stringify(dup)}`);
  else g.ok(`F4 首屏清单与按需清单（${od.set.size} 项）无重叠`);
}

// F5 首帧握手唯一性（F3-M08）：判前先剥注释——注释里引用函数名属文档，不是调用点
{
  const strip = (t) => t.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:"'`\\])\/\/[^\n]*/g, '$1');
  const fpBad = judgeFirstPaintHandshake(
    strip(readFileSync(join(SRC, 'scripts', 'tauri-api.js'), 'utf8')),
    strip(readFileSync(join(SRC, 'scripts', 'app.js'), 'utf8')),
  );
  if (fpBad.length) g.fail(`F5 首帧握手唯一性破坏：${fpBad.join('；')}`);
  else g.ok('F5 首帧握手触发点唯一（tauri-api.js 末尾 1 处）、守卫 firstPaintSent 在模块作用域、app.js 无残留调用');
}

g.finish('首屏门禁全部通过');
