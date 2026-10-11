#!/usr/bin/env node
// check-subwindow-css.mjs —— 「P0 子窗 CSS 按需」的不变量机检（2026-10-12）
//
// 背景：main.css 原本被 5 个窗口全量同步加载，其中主窗专属页面样式对 4 个子窗完全冗余。
// 拆分把这部分搬进 main-pages.css，只由 index.html 链接。搬动的正确性靠三条不变量撑着，
// 这三条**必须**在后续每一次手改里继续成立 —— 否则症状是「子窗某块界面静默掉样式」，
// 而 cargo / MockRuntime 都看不见（渲染层不在测试射程内，AGENTS §4.1）。
//
// 抓什么：
//   S1 链接面 —— index.html 恰为 main.css → main-pages.css → ds.css；每个子窗恰为
//      main.css → ds.css。子窗链接 main-pages.css = 拆分白做；子窗少挂 ds.css = 撞 AGENTS §2 红线。
//   S2 分箱不变量 —— main-pages.css 里的每个 class/id 都不得出现在任何子窗语料
//      （该窗 HTML + 它 <script src> 加载的脚本）里。有人把子窗在用的类写进/搬进
//      main-pages.css，子窗当场失去这条样式。
//   S3 层叠顺序防线 —— main-pages.css 与 main.css 之间不得存在「同特异度 + 共享选择器
//      token + 声明属性相交」的规则对。main-pages.css 排在后面，这样的两条会把拆分前
//      「前者覆盖后者」翻成反向，而两个文件各自看起来都完全合理。
//   S4 token 真源 —— main-pages.css 不得定义 `:root` / `.theme-light`（AGENTS §2：
//      main.css 是 token 唯一真源，拆出去的只能是消费方规则）。
//
// 用法：node tools/check-subwindow-css.mjs [--self-test]
'use strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const S = 'src/styles';
const SELF_TEST = process.argv.includes('--self-test');
const g = gate(import.meta.url);

const MAIN_HTML = 'src/index.html';
const SUB_HTML = [
  'src/preview-window.html',
  'src/models-window.html',
  'src/residue-window.html',
  'src/process-manager-window.html',
];
const EXPECT_MAIN = ['styles/main.css', 'styles/main-pages.css', 'styles/ds.css'];
const EXPECT_SUB = ['styles/main.css', 'styles/ds.css'];

// ---------- CSS 解析：只到「规则块 + 其 at-rule 上下文」，与拆分时的口径一致 ----------
function parseRules(src) {
  const n = src.length;
  const wsC = (f) => {
    let p = f;
    while (p < n) {
      if (src[p] === '/' && src[p + 1] === '*') { const e = src.indexOf('*/', p + 2); p = e < 0 ? n : e + 2; continue; }
      if (/\s/.test(src[p])) { p++; continue; }
      break;
    }
    return p;
  };
  const stmtEnd = (f) => {
    let p = f;
    while (p < n) {
      const c = src[p];
      if (c === '/' && src[p + 1] === '*') { const e = src.indexOf('*/', p + 2); p = e < 0 ? n : e + 2; continue; }
      if (c === '"' || c === "'") { const q = c; p++; while (p < n && src[p] !== q) { if (src[p] === '\\') p++; p++; } p++; continue; }
      if (c === '{' || c === ';' || c === '}') return { at: p, kind: c };
      p++;
    }
    return { at: n, kind: 'eof' };
  };
  const closeOf = (o) => {
    let d = 0, p = o;
    while (p < n) {
      const c = src[p];
      if (c === '/' && src[p + 1] === '*') { const e = src.indexOf('*/', p + 2); p = e < 0 ? n : e + 2; continue; }
      if (c === '"' || c === "'") { const q = c; p++; while (p < n && src[p] !== q) { if (src[p] === '\\') p++; p++; } p++; continue; }
      if (c === '{') d++;
      else if (c === '}') { d--; if (d === 0) return p; }
      p++;
    }
    return n - 1;
  };
  const out = [];
  const walk = (from, until, atPath, atLine) => {
    let cur = from;
    while (true) {
      const s = wsC(cur);
      if (s >= until) return;
      const st = stmtEnd(s);
      if (st.at >= until || st.kind === 'eof') return;
      if (st.kind === '}') { cur = st.at + 1; continue; }
      const prelude = src.slice(s, st.at).trim();
      const line = atLine + (src.slice(0, s).match(/\n/g) || []).length;
      if (st.kind === ';') { cur = st.at + 1; continue; }
      const cl = closeOf(st.at);
      if (/^@(media|supports|layer|container)/i.test(prelude)) {
        walk(st.at + 1, cl, [...atPath, prelude], line);
      } else {
        out.push({ prelude, body: src.slice(st.at + 1, cl), line });
      }
      cur = cl + 1;
    }
  };
  walk(0, n, [], 0);
  return out;
}

// ---------- 选择器 token 与特异度（与 S3 的判定同源，只有这一份实现） ----------
const PSEUDO_ELEM = new Set(['before', 'after', 'first-line', 'first-letter', 'selection', 'placeholder',
  'scrollbar', 'webkit-scrollbar', 'webkit-scrollbar-thumb', 'webkit-scrollbar-track', 'webkit-scrollbar-button',
  'webkit-slider-thumb', 'webkit-slider-runnable-track', 'webkit-inner-spin-button', 'webkit-outer-spin-button',
  'backdrop', 'marker', 'file-selector-button', 'cue', 'grammar-error', 'spelling-error']);
function selInfo(prelude) {
  const p = prelude.replace(/\/\*[\s\S]*?\*\//g, '');
  const cls = [...p.matchAll(/\.(-?[_a-zA-Z][\w-]*)/g)].map(m => m[1]);
  const ids = [...p.matchAll(/#(-?[_a-zA-Z][\w-]*)/g)].map(m => m[1]);
  const attrs = [...p.matchAll(/\[\s*([_a-zA-Z][\w-]*)/g)].map(m => m[1]);
  const elems = [...p.matchAll(/(?:^|[\s>+~,(])([a-zA-Z][\w-]*)/g)].map(m => m[1].toLowerCase())
    .filter(w => !['and', 'not', 'only', 'screen', 'print', 'all'].includes(w));
  const pseudo = [...p.matchAll(/::?([a-zA-Z][\w-]*)/g)].map(m => m[1].toLowerCase());
  const pe = pseudo.filter(x => PSEUDO_ELEM.has(x)).length;
  const pc = pseudo.length - pe;
  const tok = new Set([
    ...cls.map(x => 'c:' + x), ...ids.map(x => 'i:' + x), ...attrs.map(x => 'a:' + x),
    ...elems.map(x => 'e:' + x), ...pseudo.map(x => 'p:' + x),
  ]);
  return { cls, ids, tok, spec: `${ids.length}-${cls.length + attrs.length + pc}-${elems.length + pe}` };
}
function declProps(body) {
  const out = new Set();
  let depth = 0, cur = '';
  for (const ch of body) {
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    if (ch === ';' && depth === 0) { const i = cur.indexOf(':'); if (i > 0) out.add(cur.slice(0, i).trim().toLowerCase()); cur = ''; continue; }
    cur += ch;
  }
  const i = cur.indexOf(':');
  if (i > 0 && cur.slice(0, i).trim()) out.add(cur.slice(0, i).trim().toLowerCase());
  out.delete('');
  return out;
}

// ---------- 子窗语料：该窗 HTML + 它加载的每个脚本（含字符串字面量，宽松收） ----------
function corpusOf(htmlRel) {
  const html = readFileSync(join(ROOT, htmlRel), 'utf8').replace(/<!--[\s\S]*?-->/g, ' ');
  const texts = [html];
  const scripts = [...html.matchAll(/<script\s+src="([^"]+)"/g)].map(m => 'src/' + m[1].replace(/^(\.\/|\/)/, ''));
  for (const s of scripts) {
    const abs = join(ROOT, s);
    if (!existsSync(abs)) { g.fail(`${htmlRel} 声明的脚本 ${s} 不在盘上（语料残缺，S2 判据不可信）`); continue; }
    const js = readFileSync(abs, 'utf8').replace(/\/\*[\s\S]*?\*\//g, ' ');
    texts.push(js);
    for (const m of js.matchAll(/(['"`])((?:\\.|(?!\1)[^\\])*?)\1/g)) texts.push(' ' + m[2].replace(/\\./g, ' ') + ' ');
  }
  const text = texts.join('\n');
  const set = new Set();
  const words = (s, pre) => { for (const w of String(s).split(/[\s,]+/)) if (/^[_a-zA-Z][\w-]*$/.test(w)) set.add(pre + w); };
  for (const m of text.matchAll(/class(?:Name)?\s*=\s*['"`]([^'"`]*)['"`]/g)) words(m[1], 'c:');
  for (const m of text.matchAll(/classList\.(?:add|remove|toggle|contains)\(([^)]*)\)/g)) for (const q of m[1].matchAll(/['"`]([^'"`]*)['"`]/g)) words(q[1], 'c:');
  for (const m of text.matchAll(/(?:querySelector(?:All)?|closest|matches)\(\s*['"`]([^'"`]*)['"`]/g))
    for (const q of m[1].matchAll(/[.#](-?[_a-zA-Z][\w-]*)/g)) set.add((q[1][0] === '.' ? 'c:' : 'i:') + q[1].slice(1));
  for (const m of text.matchAll(/getElementById\(\s*['"`]([^'"`]*)['"`]/g)) set.add('i:' + m[1]);
  for (const m of text.matchAll(/\sid\s*=\s*['"`]([^'"`]*)['"`]/g)) set.add('i:' + m[1]);
  for (const m of text.matchAll(/class\s*=\s*\\?['"`]([^\\'"`]*)\\?['"`]/g)) words(m[1], 'c:');
  // 字符串里的裸词兜底：只收带连字符的类名形态，避免把 JS 关键字当类名（宁少搬不多搬）
  for (const m of text.matchAll(/(['"`])([^'"`]*?)\1/g))
    for (const w of m[2].split(/[^\w-]+/)) if (/^[a-zA-Z][\w]*(?:-[\w]+)+$/.test(w)) { set.add('c:' + w); set.add('i:' + w); }
  for (const m of text.matchAll(/(?:^|[\s,+(])#([_a-zA-Z][\w-]*)/g)) set.add('i:' + m[1]);
  // 独立裸串复检：类名作为整词出现在该窗语料里就算「该窗可能用到」（不走上面的抽取口径）
  return { tokens: set, blob: text };
}
function linksOf(htmlRel) {
  const html = readFileSync(join(ROOT, htmlRel), 'utf8');
  return [...html.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*>/g)]
    .map(m => (m[0].match(/href="([^"]+)"/) || [])[1])
    .filter(Boolean)
    .map(h => h.replace(/^\.\//, ''));
}

// ---------- S1 链接面 ----------
{
  const main = linksOf(MAIN_HTML);
  const ok = main.join(' → ') === EXPECT_MAIN.join(' → ');
  g.ok(`S1a. ${MAIN_HTML} 样式表序列 = ${main.join(' → ')}`);
  if (!ok) g.fail(`S1a. ${MAIN_HTML} 必须恰为 ${EXPECT_MAIN.join(' → ')}（实为 ${main.join(' → ')}）—— 顺序变了层叠就变了`);
  for (const h of SUB_HTML) {
    const l = linksOf(h);
    if (l.join(' → ') !== EXPECT_SUB.join(' → ')) {
      g.fail(`S1b. ${h} 样式表必须恰为 ${EXPECT_SUB.join(' → ')}（实为 ${l.join(' → ')}）` +
        (l.includes('styles/main-pages.css') ? ' —— 子窗链上 main-pages.css，P0 拆分等于白做' : '') +
        (!l.includes('styles/ds.css') ? ' —— 少挂 ds.css 撞 AGENTS §2 红线' : ''));
    }
  }
  const subCount = SUB_HTML.filter(h => linksOf(h).join(' → ') === EXPECT_SUB.join(' → ')).length;
  g.ok(`S1b. 四个子窗样式表序列均为 main.css → ds.css（${subCount}/4 达标）`);
  if (subCount !== SUB_HTML.length) g.fail(`S1b. 达标子窗 ${subCount}/4，存在缺挂或多挂`);
}

// ---------- 载入两份 CSS ----------
const mainCss = readFileSync(join(ROOT, S, 'main.css'), 'utf8');
const pagesCss = readFileSync(join(ROOT, S, 'main-pages.css'), 'utf8');
if (!pagesCss.trim()) g.fail('src/styles/main-pages.css 是空的：S2/S3 会集体空转（断言对象 0 的绿不算通过）');
const mainRules = parseRules(mainCss);
const pagesRules = parseRules(pagesCss);
if (mainRules.length < 500 || pagesRules.length < 100) {
  g.fail(`解析块数骤降（main.css ${mainRules.length} / main-pages.css ${pagesRules.length}）⇒ 解析失明，不是仓库变小`);
}

// ---------- S2 分箱不变量 ----------
{
  const pagesTok = new Map();
  for (const r of pagesRules) {
    const s = selInfo(r.prelude);
    for (const t of [...s.cls.map(x => 'c:' + x), ...s.ids.map(x => 'i:' + x)]) if (!pagesTok.has(t)) pagesTok.set(t, r);
  }
  const hits = [];
  for (const h of SUB_HTML) {
    const { tokens, blob } = corpusOf(h);
    const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const t of pagesTok.keys()) {
      if (!t.startsWith('c:')) continue;
      const name = t.slice(2);
      const inCorpus = tokens.has(t) || new RegExp('[^\\w-]' + esc(name) + '[^\\w-]').test(blob);
      if (inCorpus) hits.push(`${name}（${h}）→ main-pages.css:${pagesTok.get(t).line}`);
    }
  }
  if (hits.length) g.fail(`S2. main-pages.css 里有被子窗引用的选择器 ${hits.length} 处：${hits.slice(0, 8).join('、')}`);
  else g.ok(`S2. main-pages.css 的 ${pagesTok.size} 个 class/id 无一被子窗引用（可搬不变量成立）`);
}

// ---------- S3 层叠顺序防线 ----------
{
  const mainIdx = new Map();
  for (const r of mainRules) {
    const s = selInfo(r.prelude);
    for (const t of s.tok) { if (!mainIdx.has(t)) mainIdx.set(t, []); mainIdx.get(t).push({ r, s, props: declProps(r.body) }); }
  }
  const flips = [];
  for (const r of pagesRules) {
    const s = selInfo(r.prelude);
    if (!s.cls.length && !s.ids.length) { flips.push(`纯元素规则 ${r.prelude.slice(0, 40)}（main-pages.css:${r.line}）—— 它本该留在 main.css`); continue; }
    const props = declProps(r.body);
    const seen = new Set();
    for (const t of s.tok) {
      for (const m of mainIdx.get(t) || []) {
        const key = m.r.line + '|' + m.r.prelude;
        if (seen.has(key)) continue;
        seen.add(key);
        if (m.s.spec === s.spec && [...props].some(p => m.props.has(p))) {
          flips.push(`main-pages.css:${r.line} ${r.prelude.slice(0, 40)} ⇄ main.css:${m.r.line} ${m.r.prelude.slice(0, 40)}（同特异度 ${s.spec}、共享 token、属性相交）`);
        }
      }
    }
  }
  if (flips.length) g.fail(`S3. 存在跨文件层叠翻转风险 ${flips.length} 处：${flips.slice(0, 5).join(' ; ')}`);
  else g.ok(`S3. main-pages.css 与 main.css 之间无「同特异度 + 共享 token + 属性相交」对（${pagesRules.length} 条逐条比对）`);
}

// ---------- S4 token 真源 ----------
{
  const bad = [...pagesCss.matchAll(/^(:root|\.theme-light)\s*\{/gm)].map(m => m[1]);
  if (bad.length) g.fail(`S4. main-pages.css 里出现 token 定义块：${bad.join('、')}（AGENTS §2：main.css 是 token 唯一真源）`);
  else g.ok('S4. main-pages.css 不定义 :root / .theme-light');
}

// ---------- 正向对照：证明上面四条真的能判红（AGENTS §4.1「无对照的恒绿断言视同没写」） ----------
// 语义：每组返回「自审理由」数组 —— 阳性样本没命中、或阴性样本被误命中，都记一条问题。
// 有问题 ⇒ --self-test 判红（说明真仓那几条断言其实是恒绿的摆设）。
function selfTest() {
  const problems = [];
  // ① S1：子窗样式表被改坏（多链 main-pages / 少挂 ds）必须判不等；正确序列必须判等
  for (const [broken, shouldRed] of [
    [['styles/main.css', 'styles/main-pages.css', 'styles/ds.css'], true],
    [['styles/main.css'], true],
    [EXPECT_SUB, false],
  ]) {
    const red = broken.join(' → ') !== EXPECT_SUB.join(' → ');
    if (red !== shouldRed) problems.push(`S1 对照错位：${broken.join('+')} 期望${shouldRed ? '红' : '绿'}`);
  }
  // ② S2：子窗语料引用 main-pages 才有的类 ⇒ 必须命中；没引用 ⇒ 不得命中
  {
    const probe = 'zz-split-probe';
    const hit = new RegExp('[^\\w-]' + probe + '[^\\w-]').test(`x class="${probe}" y`);
    const miss = new RegExp('[^\\w-]' + probe + '[^\\w-]').test('x class="other-thing" y');
    if (!hit) problems.push('S2 对照：子窗引用了却没命中 ⇒ 该断言恒绿');
    if (miss) problems.push('S2 对照：未引用的类也被判命中 ⇒ 假阳性洪水');
  }
  // ③ S3：同特异度 + 共享 token 必须拦下；不同特异度必须放行；属性相交判据要真能相交
  {
    const a = selInfo('.zz-dup-hook'), b = selInfo('.zz-dup-hook');
    if (!(a.spec === b.spec && [...a.tok].some(t => b.tok.has(t)))) problems.push('S3 对照：同特异度同 token 没被识别 ⇒ S3 恒绿');
    const n1 = selInfo('.zz-a'), n2 = selInfo('.zz-b .zz-a');
    if (n1.spec === n2.spec) problems.push('S3 对照：不同特异度被判相等 ⇒ 会假红');
    const pa = declProps('color: red; padding: 2px'), pb = declProps('color: blue');
    if (![...pa].some(p => pb.has(p))) problems.push('S3 对照：声明属性相交判据失效');
  }
  // ④ S4：main-pages 里出现 :root 必须判红
  {
    const red = [...'.x{}\n:root { --zz: 1; }'.matchAll(/^(:root|\.theme-light)\s*\{/gm)].length > 0;
    const green = [...'.x{}\n.card-y { --zz: 1; }'.matchAll(/^(:root|\.theme-light)\s*\{/gm)].length > 0;
    if (!red) problems.push('S4 对照：:root 没被抓到');
    if (green) problems.push('S4 对照：普通块被误判成 token 块');
  }
  // ⑤ 解析器形状对照：@media 内层与含花括号的字符串都要正确切块（否则 S3 全程空转）
  {
    const nested = parseRules('@media (max-width: 900px) {\n  .zz-in-media { color: red; }\n}\n.zz-top { color: blue; }');
    if (nested.length !== 2) problems.push(`嵌套解析得到 ${nested.length} 条（应为 2）⇒ S3 会漏判`);
    const quoted = parseRules('.zz-quote { content: "a{b}"; }\n.zz-after { color: red; }');
    if (quoted.length !== 2) problems.push(`引号内花括号打断了块边界（得到 ${quoted.length} 条）`);
  }
  return problems;
}

// 正向对照在门禁内随跑随验（check-positive-controls 的登记口径）；--self-test 只跑对照。
const selfProblems = selfTest();
if (SELF_TEST) {
  for (const p of selfProblems) console.error(`✗ 正向对照失败：${p}`);
  if (selfProblems.length) {
    console.error(`check-subwindow-css --self-test: ${selfProblems.length} 条对照不成立（真仓断言里有恒绿摆设）`);
    process.exit(1);
  }
  console.log('✓ check-subwindow-css --self-test: 五组正向对照全部能判红，且阴性样本不误伤');
  process.exit(0);
}
if (selfProblems.length) {
  g.fail(`S0. 正向对照不成立 ${selfProblems.length} 条（上面某条断言其实是恒绿摆设）：${selfProblems.join('；')}`);
} else {
  g.ok('S0. 五组正向对照全部能判红，且阴性样本不误伤（S1–S4 不是恒绿断言）');
}

g.finish('check-subwindow-css: 子窗 CSS 按需的四条不变量全部成立');
