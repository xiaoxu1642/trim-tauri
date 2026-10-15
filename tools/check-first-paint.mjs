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
import { readFileSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT } from './ps-origin.mjs';
import { gate } from './lib/gate.mjs';

const SRC = join(REPO_ROOT, 'src');
const HTML = join(SRC, 'index.html');
const APP_JS = join(SRC, 'scripts', 'app.js');

// ---- 预算（现算于 2026-10-15，v5 P1 编辑器 + P2 四项落地后）----
// 沿革：v5 P0 增补 9 条 syspanel 桥接后为 701,385 B，上限 702,000 B（贴值留余）。
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
const CAP_MAX = 718_500;
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

// ---------- 解析 ----------
function parseHtml() {
  const html = readFileSync(HTML, 'utf8');
  const scripts = [];
  const re = /<script([^>]*)\ssrc="([^"]+)"([^>]*)><\/script>/g;
  for (const m of html.matchAll(re)) {
    const rel = m[2].replace(/^(\.\.\/|\.\/|\/)+/, '').replace(/^src\//, '');
    scripts.push({
      rel,
      defer: /\bdefer\b/.test(`${m[1]} ${m[3]}`),
      size: existsSync(join(SRC, rel)) ? statSync(join(SRC, rel)).size : -1,
    });
  }
  const css = [];
  for (const m of html.matchAll(/<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>/g)) {
    const rel = m[1].replace(/^(\.\.\/|\.\/|\/)+/, '').replace(/^src\//, '');
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
g.ok(`正向对照自检 ${selfGroups} 组全部命中（F2 违例必红 + 合规必放行、F1 超上限 + 跌破下限 + 干净放行、F4 重叠必红 + 无重叠放行）`);

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

// F4 首屏 ∩ 按需
const od = parseOnDemand();
if (!od.okPage || !od.okIdle) {
  g.fail(`F4 无法在 app.js 里定位 ${od.okPage ? '' : 'PAGE_SCRIPTS '}${od.okIdle ? '' : 'IDLE_SCRIPTS'}—— 锚点变了，请同步本门禁（不许删本断言）`);
} else {
  const dup = judgeOverlap(scripts.map((s) => s.rel), od.set);
  if (dup.length) g.fail(`F4 ${dup.length} 个脚本既在 index.html 静态挂载、又在按需清单里（白挂字节或没摘净）：${JSON.stringify(dup)}`);
  else g.ok(`F4 首屏清单与按需清单（${od.set.size} 项）无重叠`);
}

g.finish('首屏门禁全部通过');
