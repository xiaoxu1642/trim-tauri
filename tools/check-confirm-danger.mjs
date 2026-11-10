// check-confirm-danger.mjs —— app 确认入口「调用形态 + 原生兜底」门禁（审查 L3 2026-10-01 NEW-1）
//
// 为什么判红：window.app.confirmDanger / confirmWarning / confirm 是**位置参数**契约
// （app.js：confirm(title, message, confirmText, cancelText, options)）。cleanup.js 的
// offerTrashRetry 曾以「单对象」形态调用 confirmDanger（L3 NEW-1）：对象被当 title
// 渲染成 "[object Object]"，正文空白、「永久删除不可恢复」危险警示整段丢失——
// 而这条链是绕过回收站的不可逆永久删除确认。check-channel-map 只对通道名，
// 抓不到「通道对、参数形态错」这类回归，故单独立门禁。
//
// 判定：src/scripts/*.js 中以下调用形态即红（首参为对象字面量 `{`）：
//   · 裸标识符 confirmDanger( / confirmWarning(
//   · app.confirmDanger / app.confirmWarning / app.confirm（含 ?. 可选链）
// 注意：window.modal.confirm({…}) 是合法契约（modal 层本就收对象参数），不在判定范围。
//
// 判定二（P0-5，2026-10-15）：渲染层再出现**原生确认框兜底**即红 —— window.confirm /
// window.alert / window.prompt（含可选链写法）。为什么判红：确认件缺席时「回退原生框」
// 是 fail-open 形态，本仓两处（app.js 确认总入口、cleanup.js 删图确认）已在 P0-5 同批
// 改为 fail-closed；回退方向错了渲染层没有任何别的门禁看得见（check-fail-closed 的判据面
// 是 Rust 侧）。与前两组同属「确认这件事的调用形态」职责面，故不再单开文件（同名门禁
// check-fail-closed 已被 Rust 侧占用，前端这条别复用那个名字）。
// 注释剥离：块注释整块剥离（等长替换保行号）；命中行若其前缀含 `//` 视为注释跳过。
// 模板字符串里的形似文本理论上可能误红——出现时改措辞即可，不要为此放松匹配。
// 运行时最后防线：app.js confirmDanger/confirmWarning 内置对象归一兜底（NEW-1 修复），
// 但兜底不豁免本门禁——调用点必须在源头上写对。
//
// 判红验证：任一 src/scripts/*.js 临时加 `window.app?.confirmDanger({ title: 'x' });`
// → 本门禁必须红（exit 1）；移除后恢复绿。
// 原生兜底组同理：临时加一行原生 window.confirm 调用 → 必须红；移除后恢复绿。
//
// 用法：node tools/check-confirm-danger.mjs

import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkFiles } from './lib/fs-walk.mjs';
import { blankNonCode } from './lib/src-scan.mjs';

const dir = join(REPO_ROOT, 'src', 'scripts');
// T1a-L04：递归（scripts 子目录里的 JS 也纳入确认框判据）。
const files = walkFiles(dir, (f) => f.endsWith('.js'))
  .map((p) => relative(dir, p).replace(/\\/g, '/')).sort();

// 扫描面地板（P0-4）：目录塌陷/改名 ⇒ files=[]，末尾「✓ 0 个脚本无对象形态调用」是空集假绿。
// 下限 10 是明显下界——只拦整目录塌陷，不拦正常增删。
if (files.length < 10) {
  console.error(`✗ src/scripts 只剩 ${files.length} 个 .js ⇒ 扫描面塌陷，拒绝判绿`);
  process.exit(1);
}

// 剥离块注释（等长替换保偏移量与行号），行注释在命中处按行前缀判定
function stripBlockComments(text) {
  return blankNonCode(text, 'js', { keepStrings: true, lineComments: false });
}
/**
 * T1a-L03：命中点之前是否已进入**行注释**——必须跳过字符串字面量里的 `//`。
 * 旧判据 `before.includes('//')` 在 `const u = 'https://x'; window.app.confirmDanger({…})`
 * 这种同一行前缀含 URL 的真实调用上整条跳过（字符串里的 `//` 被当成注释起点）。
 */
function inLineComment(text, idx) {
  const lineStart = text.lastIndexOf('\n', idx - 1) + 1;
  let q = null;
  for (let i = lineStart; i < idx; i++) {
    const c = text[i];
    if (q) {
      if (c === '\\') { i++; continue; }
      if (c === q) q = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { q = c; continue; }
    if (c === '/' && text[i + 1] === '/') return true;
  }
  return false;
}

// 注意必须带 g 标志：exec 循环依赖 lastIndex 推进，无 g 时同一首匹配永远返回 → 死循环
// （判红验证实测抓出：无匹配时毫秒级绿跑，一旦有匹配即挂死）
const RE_BARE = /(?:^|[^\w.$])(?:confirmDanger|confirmWarning)\s*\(\s*\{/g;
const RE_APP = /\bapp\s*\??\.confirm(?:Danger|Warning)?\s*\(\s*\{/g;
// P3-5（v4-K05）：高危确认凭据不得硬编码 —— `confirmedHighRisk: true` 字面量出现在
// 渲染层（含桥接层）即红：凭据必须由调用点从确认结果派生（变量 / `!!x`）传入，
// 硬编码 true 等于把安全门拆掉（v2-F4 历史形态）。局部对象赋值（`= true`，且上游
// 刚 await 过确认）不在判定面。
const RE_HARDCODED_CRED = /confirmedHighRisk\s*:\s*true\b/g;
// P0-5：原生确认框兜底形态。前缀用**固定宽度 lookbehind** 守卫、不消费字符——消费式
// `(?:^|[^\w.$])` 会把命中起点左移到前缀字符上，让紧贴行首的注释样本（//window.…）漏跳
// （§4.1② 同族的假阳性陷阱：负向断言要写稳，别让回溯命中半个标识符）。
// 覆盖形态：window.confirm( / window.confirm?.( / window?.confirm(（声明间空白任意）。
const RE_NATIVE_FALLBACK = /(?<![\w.$])window\s*(?:\?\.)?\.?\s*(?:confirm|alert|prompt)\s*(?:\?\.)?\s*\(/g;
// 正向对照自检（合成样本，见文末）
function hardcodedCredViolations(text) {
  return [...text.matchAll(RE_HARDCODED_CRED)].map((m) => m[0]);
}
// 同一判定器（RE_NATIVE_FALLBACK）供扫描与自检共用，不另抄第二套判据
function nativeFallbackViolations(text) {
  return [...text.matchAll(RE_NATIVE_FALLBACK)].map((m) => m[0]);
}

// B3-2 / B3-3：确认件必须**在 try 内** await。确认框自己抛错时，若 await 在 try 之外，
// 异常就落进 async handler 变成无人接的 rejection —— 界面零提示、按钮停在中间态
// （cleanup.js 的「正在登记...」、startup.js 的批量启停），用户只看到「点了没反应」。
// 判据面刻意只收 `window.app` 前缀：`window.modal.confirm({...})` 是另一层契约（对象参数、
// 组件缺席即 fail-closed），它的 await 位置由那段代码自己的 try 管，不并入本判据。
const RE_AWAIT_APP_CONFIRM = /\bawait\s+window\s*\.\s*app\s*\??\.\s*confirm(?:Danger|Warning)?\s*\(/g;
// F4a1-M18：uninstall.js 的确认调用使用 `confirmDanger?.(` 可选链形态；
// 其它历史调用点仍按原判据（不在本次范围，避免把 30+ 处存量一次拖红）。
const RE_AWAIT_APP_CONFIRM_OPTIONAL = /\bawait\s+window\s*\.\s*app\s*\??\.\s*confirm(?:Danger|Warning)?\s*\?\.\s*\(/g;
/**
 * 返回「不在 try 内」的命中下标。判定＝命中之前最近的 `try {` 与命中之间没有 catch 闭合，
 * 且命中之后能找到同一个 try 的 `} catch`。源码级近似（不做括号配对），对本仓写法足够；
 * 要精确必须上 AST —— 那会把这条门禁变成解析器工程，收益不成比例。
 *
 * T1a-L03：`try {` / `} catch` 的搜索改在**剥注释与字符串**之后的文本上做（等长抹除，
 * 偏移与原文一一对应）。旧实现直接搜原文：`try {` 只出现在行注释里时会被当成真 try，
 * 把「不在 try 内」误判成 inside —— 一条说明文字就能翻转 try 归属。
 */
function confirmOutsideTry(text, clean = blankNonCode(text, 'js', { keepStrings: true }), optionalChain = false) {
  const out = [];
  const re = optionalChain ? RE_AWAIT_APP_CONFIRM_OPTIONAL : RE_AWAIT_APP_CONFIRM;
  for (const m of text.matchAll(re)) {
    const t = clean.lastIndexOf('try {', m.index);
    let inside = false;
    if (t >= 0) {
      const between = clean.slice(t, m.index);
      const after = clean.slice(m.index);
      inside = !/\}\s*catch\b/.test(between) && /\}\s*catch\b/.test(after);
    }
    if (!inside) out.push(m.index);
  }
  return out;
}
// 逐文件基线（只减不增）：B3-2/B3-3 范围内的 cleanup.js / startup.js 已归零；余下是**已登记的
// 债**（本批范围外），每降一处就把数字改小或删键。新文件进场即红 —— 别往表里塞条目凑绿。
const CONFIRM_TRY_BASELINE = {
  'cleanup.js': 7,
  'maintenance.js': 1,
  'netcheck.js': 2,
  'optimizer.js': 8,
};

const bad = [];
const hardcoded = [];
const nativeFallback = [];
const outsideTry = [];
const grow = [];
for (const f of files) {
  const text = stripBlockComments(readFileSync(join(dir, f), 'utf8'));
  for (const re of [RE_BARE, RE_APP]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (inLineComment(text, m.index)) {
        // 行注释里的形似文本（整行注释或行尾注释），跳过
        re.lastIndex = m.index + m[0].length;
        continue;
      }
      const line = text.slice(0, m.index).split('\n').length;
      bad.push(`${f}:${line}`);
      re.lastIndex = m.index + m[0].length;
    }
  }
  // P3-5：凭据字面量检查（行注释跳过，注释里的提及不算数）
  RE_HARDCODED_CRED.lastIndex = 0;
  let h;
  while ((h = RE_HARDCODED_CRED.exec(text)) !== null) {
    if (inLineComment(text, h.index)) continue;
    hardcoded.push(`${f}:${text.slice(0, h.index).split('\n').length}`);
  }
  // B3-2/B3-3：确认件 await 的 try 归属（逐文件计数，与基线比）
  {
    const hits = confirmOutsideTry(text, blankNonCode(text, 'js', { keepStrings: true }), f.endsWith('uninstall.js'));
    if (hits.length > (CONFIRM_TRY_BASELINE[f] ?? 0)) {
      for (const idx of hits.slice(0, 3)) {
        outsideTry.push(`${f}:${text.slice(0, idx).split(String.fromCharCode(10)).length}`);
      }
      grow.push(`${f} ${CONFIRM_TRY_BASELINE[f] ?? 0}→${hits.length}`);
    }
  }

  // P0-5：原生框兜底（行注释跳过，同前）
  RE_NATIVE_FALLBACK.lastIndex = 0;
  let nf;
  while ((nf = RE_NATIVE_FALLBACK.exec(text)) !== null) {
    if (inLineComment(text, nf.index)) continue;
    nativeFallback.push(`${f}:${text.slice(0, nf.index).split('\n').length}`);
  }
}

// 正向对照自检（合成样本）
{
  const POSITIVE_CONTROLS = {
    bad: 'window.api.syspanel.pagefileApply(true, [], { confirmedHighRisk: true });',
    good: 'window.api.syspanel.pagefileApply(true, [], { confirmedHighRisk: !!ok });\nrunParams.confirmedHighRisk = true;',
  };
  const b = hardcodedCredViolations(POSITIVE_CONTROLS.bad).length;
  const g2 = hardcodedCredViolations(POSITIVE_CONTROLS.good).length;
  if (b !== 1 || g2 !== 0) {
    console.error(`✗ 正向对照失败：字面量样本命中 ${b}（应 1）/ 合规样本命中 ${g2}（应 0）`);
    process.exit(1);
  }
  // P0-5：原生框兜底判定器 —— 违规样本必须命中、合规样本必须放行
  const NF_CONTROLS = {
    bad: "if (!window.modal) return window.confirm('继续吗？');",
    good: "const ok = await window.modal.confirm({ title: '确认' });\nwindow.app?.toast?.('error', '确认组件未加载，本次不执行任何改动');",
  };
  const nb = nativeFallbackViolations(NF_CONTROLS.bad).length;
  const ng = nativeFallbackViolations(NF_CONTROLS.good).length;
  if (nb !== 1 || ng !== 0) {
    console.error(`✗ 正向对照失败：原生兜底样本命中 ${nb}（应 1）/ 合规样本命中 ${ng}（应 0）`);
    process.exit(1);
  }
  // B3-2/B3-3：确认件 try 归属判定器 —— 无 try 的必须命中、包在 try 里的必须放行
  const TRY_CONTROLS = {
    bad: "const ok = await window.app.confirm('x', 'y');\nif (!ok) return;",
    good: "try {\n  const ok = await window.app.confirm('x', 'y');\n  if (!ok) return;\n} catch (e) {\n  return;\n}",
    // T1a-L03：`try {` 只出现在行注释里不得被当成真 try（旧实现整条误判 inside）
    commentTry: "// try { 这里只是说明写法\nconst ok = await window.app.confirm('x', 'y');\n} catch (e) { return; }",
  };
  const tb = confirmOutsideTry(TRY_CONTROLS.bad).length;
  const tg = confirmOutsideTry(TRY_CONTROLS.good).length;
  const tc = confirmOutsideTry(TRY_CONTROLS.commentTry).length;
  if (tb !== 1 || tg !== 0 || tc !== 1) {
    console.error(`✗ 正向对照失败：确认件 try 归属样本命中 ${tb}（应 1）/ 合规样本命中 ${tg}（应 0）/ 注释 try 命中 ${tc}（应 1）`);
    process.exit(1);
  }
  // T1a-L03：行注释判定器 —— 字符串里的 `//` 不得把真实调用洗成注释；真注释仍要跳过
  const urlLine = "const u = 'https://x'; window.app.confirmDanger({ title: 'x' });";
  const commentLine = "// window.app.confirmDanger({ title: 'x' });";
  const urlAt = urlLine.indexOf('confirmDanger');
  const commentAt = commentLine.indexOf('confirmDanger');
  const lc = inLineComment(urlLine, urlAt);
  const lcm = inLineComment(commentLine, commentAt);
  if (lc || !lcm) {
    console.error(`✗ 正向对照失败：行注释判定器把 URL 行判成注释=${lc}（应 false）/ 真注释行判成代码=${!lcm}（应 false）`);
    process.exit(1);
  }
  console.log('✓ 正向对照自检通过（凭据字面量判定器可判红、合规样本放行；原生兜底判定器可判红、合规样本放行；确认件 try 归属判定器可判红、合规样本放行；行注释判定器 URL 不算注释、真注释跳过）');
}

console.log('=== app 确认入口门禁（调用形态 + 原生兜底）===\n');
if (bad.length) {
  for (const b of bad) {
    console.error(`✗ src/scripts/${b} — 确认入口首参传对象字面量（会被当 title 渲染成 "[object Object]"，危险警示整段丢失；NEW-1 回归形态）`);
  }
} else {
  console.log(`✓ ${files.length} 个 src/scripts 脚本无「对象形态调用 app 确认入口」`);
}
if (hardcoded.length) {
  for (const h of hardcoded) {
    console.error(`✗ src/scripts/${h} — confirmedHighRisk 被字面量为 true（高危确认凭据硬编码 = 绕过安全门；v4-K05 回归形态）`);
  }
} else {
  console.log('✓ 渲染层无 confirmedHighRisk 字面量（凭据均由调用点从确认结果派生）');
}
if (nativeFallback.length) {
  for (const n of nativeFallback) {
    console.error(`✗ src/scripts/${n} — 原生确认框兜底（组件缺席时不得回退 window.confirm / window.alert / window.prompt，应 fail-closed 中止；P0-5 回归形态）`);
  }
} else {
  console.log('✓ 渲染层无原生确认框兜底（window.confirm / window.alert / window.prompt 零命中）');
}

if (grow.length) {
  for (const g of grow) {
    console.error(`✗ ${g} — 确认件 await 不在 try 内（会变成无人接的 rejection：界面零提示、按钮卡在中间态）`);
  }
  for (const o of outsideTry) {
    console.error(`✗ src/scripts/${o} — 确认件必须在 try 内 await（B3-2/B3-3 回归形态）`);
  }
} else {
  console.log('✓ 确认件 await 的 try 归属不高于基线（B3-2/B3-3 范围内 cleanup.js / startup.js 均为 0）');
}

// F4b-L08：清空全部网速报告必须与 diskbench「清空历史」同档（confirmDanger）。
{
  const rt = readFileSync(join(dir, 'realtime.js'), 'utf8');
  const at = rt.indexOf(".rt-clear-all");
  const block = at >= 0 ? rt.slice(at, at + 2200) : '';
  const judge = (text) => {
    const i = text.indexOf('.rt-clear-all');
    if (i < 0) return false;
    const seg = text.slice(i, i + 2200);
    return seg.includes('confirmDanger');
  };
  const good = "backdrop.querySelector('.rt-clear-all').addEventListener('click', async () => {\n  const ok = await window.app?.confirmDanger?.('清空', '不可恢复');\n});";
  const bad = "backdrop.querySelector('.rt-clear-all').addEventListener('click', async () => {\n  const ok = await window.app?.confirm?.('清空', '不可恢复');\n});";
  if (!judge(good) || judge(bad)) {
    console.error('✗ 正向对照失败：网速报告清空确认档位判定器失真');
    process.exit(1);
  }
  if (!block || !block.includes('confirmDanger')) {
    console.error('✗ src/scripts/realtime.js — 「清空全部网速报告」仍走普通 confirm（应与测速历史清空同档 confirmDanger）');
    process.exit(1);
  }
  console.log('✓ 清空全部网速报告走 confirmDanger（与测速历史清空同档）');
}

// F4a2-L47：外设「应用到注册表」与「恢复 Windows 默认」同档（总方案 §9 拍板记录 1）。
{
  const pt = readFileSync(join(dir, 'peripheral.js'), 'utf8');
  const at = pt.indexOf('#btnPeriApply');
  const block = at >= 0 ? pt.slice(at, at + 2200) : '';
  const judge = (text) => {
    const i = text.indexOf('#btnPeriApply');
    if (i < 0) return false;
    return text.slice(i, i + 2200).includes('confirmDanger');
  };
  const good = "backdrop.querySelector('#btnPeriApply')?.addEventListener('click', async () => {\n  const ok = await window.app?.confirmDanger?.('应用', '写入注册表');\n});";
  const bad = "backdrop.querySelector('#btnPeriApply')?.addEventListener('click', async () => {\n  const resp = await window.api.peripheralWindow.apply({});\n});";
  if (!judge(good) || judge(bad)) {
    console.error('✗ 正向对照失败：外设应用确认档位判定器失真');
    process.exit(1);
  }
  if (!block || !block.includes('confirmDanger')) {
    console.error('✗ src/scripts/peripheral.js — 「应用到注册表」仍缺少 confirmDanger（应与恢复默认同档）');
    process.exit(1);
  }
  console.log('✓ 外设「应用到注册表」走 confirmDanger（与恢复 Windows 默认同档）');
}

console.log('');

// ---------- C-06（F4a1-L13）：红色高危确认的按钮文案必须统一 ----------
// AGENTS §3：「高危确认对话框的默认焦点在主按钮（用户 2026-10-03 拍板）」，
// 配套口径是**红色按钮 + 「仍然执行」措辞 + 结构化警示**。本组判据盯措辞：
// 按钮上写「确认清理」「仍然清理」这类动作名，会让用户把红色按钮读成「清理按钮」，
// 而不是「这一步不可逆，你确认要执行」——护栏的位置对了，牌子却挂错了。
// 动作名（清理/登记/清空回收站…）应当放进**正文**。
//
// 显式例外：某些动作需要按钮直陈其名（「清空回收站」），登记在 EXCEPTIONS 里并写明理由。
const DANGER_BUTTON_TEXT = '仍然执行';
// 两类例外：
// ① **刻意保留**：按钮直陈其名更少歧义（如「清空回收站」——用户要清的是那个具名容器）。
// ② **存量未统一（已收口 2026-11-10）**：本方案只点名了少数几处，其余存量此前登记在此，
//    现已全部统一为「仍然执行」并移出表（见回执 §4.5 / 收口遗留 C-06）。表收敛到仅 1 条
//    刻意保留项；此后任何 confirmDanger 调用按钮文案非「仍然执行」即判红（只减不增）。
const DANGER_BUTTON_EXCEPTIONS = [
  {
    file: 'cleanup.js',
    text: '清空回收站',
    reason: '该动作清空的是「回收站」这个具名容器，按钮直陈其名比「仍然执行」更少歧义（用户知道要清的是回收站）',
  },
];
{
  // 找 `confirmDanger(` 调用点，取其**第三个位置参数**（title, message, okText）。
  // 解析按括号深度走：title/message 里的逗号、括号、字符串都不能提前截断。
  function thirdArgOfDangerCall(text, callIdx) {
    let i = callIdx;
    let depth = 0;
    let argStart = -1;
    let argIndex = 0;
    let q = null;
    for (; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '\\') { i++; continue; }
        if (c === q) q = null;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') { q = c; continue; }
      if (c === '(' || c === '[' || c === '{') {
        depth++;
        if (depth === 1 && c === '(') { argStart = i + 1; argIndex = 0; }
        continue;
      }
      if (c === ')' || c === ']' || c === '}') {
        depth--;
        if (depth === 0) return null; // 参数表没走完就闭合了 ⇒ 形态异常，不判
        continue;
      }
      if (c === ',' && depth === 1) {
        argIndex++;
        if (argIndex === 2) {
  // 第三个参数：从这个逗号后到下一个顶层逗号或闭括号。
          const rest = text.slice(i + 1);
          let d = 0;
          let qq = null;
          for (let k = 0; k < rest.length; k++) {
            const cc = rest[k];
            if (qq) {
              if (cc === '\\') { k++; continue; }
              if (cc === qq) qq = null;
              continue;
            }
            if (cc === '"' || cc === "'" || cc === '`') { qq = cc; continue; }
            if (cc === '(' || cc === '[' || cc === '{') { d++; continue; }
            if (cc === ')' || cc === ']' || cc === '}') {
              if (d === 0) return rest.slice(0, k).trim();
              d--;
              continue;
            }
            if (cc === ',' && d === 0) return rest.slice(0, k).trim();
          }
          return rest.trim();
        }
        continue;
      }
    }
    return null;
  }

  const RE_DANGER_CALL = /\bconfirmDanger\s*(?:\?\.)?\s*\(/g;
  const badButtons = [];
  let dangerCalls = 0;
  for (const f of files) {
    const text = readFileSync(join(dir, f), 'utf8');
    const clean = stripBlockComments(text);
    for (const m of text.matchAll(RE_DANGER_CALL)) {
      if (inLineComment(text, m.index)) continue;
      const arg = thirdArgOfDangerCall(clean, m.index);
      if (arg === null) continue; // 形态异常（不是位置参数形态）——不在本组判据面
      dangerCalls++;
      const literal = arg.match(/^(['"])([\s\S]*?)\1$/);
      if (!literal) continue; // 非常量文案（变量传入）——不在本组判据面
      const btn = literal[2];
      if (btn === DANGER_BUTTON_TEXT) continue;
      const excused = DANGER_BUTTON_EXCEPTIONS.some(
        (e) => e.file === f && e.text === btn,
      );
      if (excused) continue;
      badButtons.push(`${f}: 高危确认按钮文案「${btn}」应为「${DANGER_BUTTON_TEXT}」（动作名请放正文）`);
    }
  }
  if (badButtons.length) {
    for (const b of badButtons) console.error(`✗ ${b}`);
    console.error(`✗ C-06 高危确认按钮文案回归：${badButtons.length} 处`);
    process.exit(1);
  }
  // 判红自证：旧文案「确认清理」必须被判红，新文案放行。
  {
    const sampleBad = "await window.app?.confirmDanger('t', 'm', '确认清理', '取消');";
    const sampleGood = "await window.app?.confirmDanger('t', 'm', '仍然执行', '取消');";
    const judge = (src) => {
      const arg = thirdArgOfDangerCall(stripBlockComments(src), src.indexOf('confirmDanger'));
      if (arg === null) return false;
      const literal = arg.match(/^(['"])([\s\S]*?)\1$/);
      if (!literal) return false;
      return literal[2] !== DANGER_BUTTON_TEXT;
    };
    if (!judge(sampleBad) || judge(sampleGood)) {
      console.error('✗ C-06 正向对照失败：高危按钮文案判定器失真（旧文案必须判红、新文案必须放行）');
      process.exit(1);
    }
  }
  console.log(`✓ C-06 高危确认按钮文案统一为「${DANGER_BUTTON_TEXT}」（${dangerCalls} 处 confirmDanger 调用；例外 ${DANGER_BUTTON_EXCEPTIONS.length} 条）`);
}

console.log('');
if (bad.length > 0 || hardcoded.length > 0 || nativeFallback.length > 0 || grow.length > 0) {
  console.error('门禁失败：确认入口调用形态/凭据/原生兜底/try 归属回归（见上）');
  process.exit(1);
}
console.log('确认入口门禁通过');
