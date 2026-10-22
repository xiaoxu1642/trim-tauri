#!/usr/bin/env node
// check-cleanup-aggregates.mjs —— 磁盘清理页体积汇总的单一去重口径（dedupSize）兜点
//
// 为什么要有它：跨条目重复计账的扣减只认一处口径 —— 后端把「两条 item 覆盖到同一批文件」
// 配成无序对挂在 overlapsWith 上，渲染层只有 dedupSize() 会扣「两端都在本次求和集合内」的
// 重叠字节。真机依据（2026-10-22 gfx）：整树统计型条目报的体积与另一条清单里同树的文件
// 逐字节相等，逐条相加把界面总量虚高到 1.6 倍（界面 976 MB、真实可清 607 MB）。
// 这类缺陷**在界面上没有症状**：数字照样合理、不报错、不 NaN，「没报错」完全不等于「没虚高」。
// 所以唯一防线是机检 —— 以后任何人图省事再写一句 reduce/+= 直接累加条目体积，就绕过扣减，
// 必须当场判红，而不是等用户再量一次盘才发现总量对不上。
//
// 判据形态（显式列举、命中即违规；不写一条泛化正则自称覆盖全部）：
//   F1  条目体积进 reduce 相加：reduce((s, i) => s + sizeNumber(
//   F2  sizeNumber 映射之后紧跟 reduce 相加：map(... sizeNumber(...) ...).reduce((a, b) => a + b
//   F3  dedupSize 函数体之外的累加赋值：+= sizeNumber(  以及  x = x + sizeNumber(
//   F4  两条条目体积直接相加后写进 Map：set(k, sizeNumber(..) + sizeNumber(..))
//   刻意不判（射程如实写明）：sizeNumber(..) + sizeNumber(..) 出现在上述四形态之外
//   （例如与第三方量相加后落变量）。真仓现算没有这种写法；要扩射程先现算再补判据 ——
//   一条泛化的「+ sizeNumber」会把「体积 + 常量」这类合法写法一起判红，误报洪水淹掉真信号。
//
// dedupSize 本体四条形态判据（S1~S4，缺一即红）：引用 overlapsWith / 扣减走 sizeNumber /
// 扣减有「两端都在集合内」的门 / 结果有非负兜底。S3/S4 各钉一条方向性缺陷：S3 被摘 →
// 只勾父条也照扣，可清量被报小；S4 被摘 → 配对重复扣时界面出现负体积。
//
// 假绿防线（AGENTS §4.1）：判据是纯函数，真仓扫描与 POSITIVE_CONTROLS 合成样本走同一实现；
// 违例样本按**命中数**断言（不是「打印红」），合规样本断言 0 命中；调用点/扫描面各设地板，
// 解析出 0 项判红而不是打 ✓。豁免登记键按 file + 判别性锚点子串、禁行号（AGENTS §5.19），
// 锚点命中 0 处或 ≥2 处都判红。
//
// 用法：node tools/check-cleanup-aggregates.mjs            # 实仓扫描 + 每次随跑自检
//       node tools/check-cleanup-aggregates.mjs --self-test # 只跑判定器自检
//       node tools/check-cleanup-aggregates.mjs --file=<路径>  # 人工取证：把真文件复制一份改坏再指给它
'use strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TARGET_REL = 'src/scripts/cleanup.js';
const TARGET = join(ROOT, 'src', 'scripts', 'cleanup.js');

const SELF_TEST_ONLY = process.argv.includes('--self-test');
const FILE_ARG = (process.argv.find((a) => a.startsWith('--file=')) || '').slice('--file='.length);

// 调用点地板：现算为 5 处（顶层分组汇总 / 子组可选总量 / 子组已选大小 / 总览 #totalSize /
// 扫描完成提示）。地板取 4 —— 少一处是重构，掉到 0 是口径被整条删空，必须判红而不是恒绿。
const CALL_FLOOR = 4;
// 扫描面地板：页内体积收敛函数的出现次数（现算 10）。塌到地板以下 = 文件被换/判定面失明，
// 此时「零违规」毫无意义（check-layering 的目录塌缩同一条纪律）。
const SIZE_NUMBER_FLOOR = 6;

/** 违规形态表（唯一的判据真源；合成样本与实仓扫描共用） */
const FORMS = [
  {
    id: 'F1',
    label: 'reduce 内联相加条目体积',
    re: /\.reduce\s*\(\s*\(\s*\w+\s*,\s*\w+\s*\)\s*=>\s*\(?\s*\w+\s*\+\s*sizeNumber\s*\(/g,
  },
  {
    id: 'F2',
    label: 'sizeNumber 映射之后紧跟 reduce 相加',
    re: /\.map\s*\([^;\n{}]{0,120}?sizeNumber\s*\([^)]*\)[^;\n{}]{0,120}?\)\s*\.reduce\s*\(\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>\s*\1\s*\+\s*\2/g,
  },
  {
    id: 'F3',
    label: 'dedupSize 体外 += 条目体积',
    re: /\+=\s*sizeNumber\s*\(/g,
  },
  {
    id: 'F3b',
    label: 'dedupSize 体外 x = x + 条目体积',
    re: /\b([A-Za-z_$][\w$]*)\s*=\s*\1\s*\+\s*sizeNumber\s*\(/g,
  },
  {
    id: 'F4',
    label: '两条条目体积直接相加后写进 Map',
    re: /\.set\s*\(\s*[^,\n)]{1,40}\s*,\s*sizeNumber\s*\([^\n;]*?\)\s*\+\s*sizeNumber\s*\(/g,
  },
];

/**
 * 已登记豁免（§5.19：file + 判别性锚点子串，禁行号）。每条必须**恰好命中 1 处**：
 * 命中 0 处 = 该形态已被改掉、豁免在替空气背书（红）；≥2 处 = 锚点失去判别力（红）。
 * 新增豁免必须写清「为什么这不是绕过扣减」，不许为了转绿而登记。
 */
const EXEMPTS = [
  {
    anchor: 'streamTotals.set(gk, sizeNumber(streamTotals.get(gk))',
    form: 'F4',
    reason:
      '扫描途中的分组过渡合计：配对两端未必都已回传，此时按 dedupSize 扣减会把「边扫边涨」的过渡值算歪，' +
      '扫描完成后的整页重渲染才落去重口径 —— 刻意不并轨，但新增同类累加一律先走 dedupSize 再谈豁免。',
  },
];

/**
 * 剥注释（等长空白化，行号/下标与原文对齐）并另出一份「结构文本」：
 * 结构文本把字符串/模板串/正则字面量的内容一并空白化，供 dedupSize 函数体做大括号配对
 * —— 字符串里的 `{` 会把体宽算错，体宽一错，体外累加就会被当成体内放过（假绿）。
 * 判据面（code）保留字符串内容：渲染层把累加写进模板串插值是真形态，洗掉等于给违规留隐蔽位。
 * 已知简化：模板串按整段处理，插值里的注释不会被剥（会把注释当代码判定，方向是误红不是漏红）；
 * 正则字面量按「前一个有效字符」启发式识别，误判成除法时其内容进判据面（同样只会误红）。
 */
function mask(src) {
  const n = src.length;
  const code = Array.from(src);
  const struct = Array.from(src);
  const blank = (arr, from, to, keepNl) => {
    for (let k = Math.max(0, from); k < Math.min(to, n); k++) {
      if (keepNl && src[k] === '\n') continue;
      arr[k] = ' ';
    }
  };
  const strEnd = (i, q) => {
    let j = i + 1;
    while (j < n && src[j] !== q) {
      if (src[j] === '\\') j++;
      j++;
    }
    return Math.min(j + 1, n);
  };
  const tmplEnd = (i) => {
    let j = i + 1;
    while (j < n && src[j] !== '`') {
      if (src[j] === '\\') j++;
      j++;
    }
    return Math.min(j + 1, n);
  };
  const regexEnd = (i) => {
    let j = i + 1;
    let cls = false;
    while (j < n) {
      const c = src[j];
      // 每个分支都必须推进 j：字符类 `[` / `]` 只改状态，漏推进会原地死循环
      //（2026-10-23 探针实测：`/["'`]/` 这类正则把整条门禁挂住，不是判红是 hang）。
      if (c === '\\') j += 2;
      else if (c === '[') { cls = true; j++; }
      else if (c === ']') { cls = false; j++; }
      else if (c === '\n') return j;
      else if (c === '/' && !cls) return j + 1;
      else j++;
    }
    return n;
  };
  let i = 0;
  let prev = '';
  while (i < n) {
    const c = src[i];
    const d = i + 1 < n ? src[i + 1] : '';
    if (c === '/' && d === '/') {
      let j = i;
      while (j < n && src[j] !== '\n') j++;
      blank(code, i, j, false);
      blank(struct, i, j, false);
      i = j;
      continue;
    }
    if (c === '/' && d === '*') {
      let j = i + 2;
      while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++;
      j = Math.min(j + 2, n);
      blank(code, i, j, true);
      blank(struct, i, j, true);
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      const j = strEnd(i, c);
      blank(struct, i + 1, j - 1, true);
      prev = c;
      i = j;
      continue;
    }
    if (c === '`') {
      const j = tmplEnd(i);
      blank(struct, i + 1, j - 1, true);
      prev = c;
      i = j;
      continue;
    }
    if (c === '/' && /[([{,=:[!&|?+\-*%~^;]$/.test(prev || '(')) {
      const j = regexEnd(i);
      blank(struct, i, j, true);
      prev = '/';
      i = j;
      continue;
    }
    if (!/\s/.test(c)) prev = c;
    i++;
  }
  return { code: code.join(''), struct: struct.join('') };
}

/** dedupSize 函数体定位（返回体宽与体文本）；解析失败返回 null，由主断言判红而不是静默放行。 */
function findDedupBody(struct) {
  const m =
    /function\s+dedupSize\s*\(/.exec(struct) ||
    /(?:const|let|var)\s+dedupSize\s*=\s*(?:async\s+)?(?:function\s*)?\(?[^)\n]*\)?\s*=>/.exec(struct);
  if (!m) return null;
  const open = struct.indexOf('{', m.index + m[0].length);
  if (open < 0) return null;
  let depth = 0;
  let i = open;
  for (; i < struct.length; i++) {
    if (struct[i] === '{') depth++;
    else if (struct[i] === '}') {
      depth--;
      if (depth === 0) break;
    }
  }
  if (i >= struct.length) return null;
  return { start: open, end: i + 1, declIndex: m.index, declEnd: m.index + m[0].length };
}

const lineAt = (text, idx) => text.slice(0, idx).split('\n').length;
const lineTextAt = (text, idx) => {
  const s = text.lastIndexOf('\n', idx) + 1;
  let e = text.indexOf('\n', idx);
  if (e < 0) e = text.length;
  return text.slice(s, e).trim();
};

/**
 * 判定器 A（纯函数）：累加形态扫描。输入已剥注释的 code 文本，返回违规清单。
 * dedupSize 体内的累加是口径实现本身（不是绕过面），按体宽整段剔除。
 */
function judgeAggregates(code) {
  const body = findDedupBody(code);
  const hits = [];
  for (const f of FORMS) {
    f.re.lastIndex = 0;
    let m;
    while ((m = f.re.exec(code)) !== null) {
      if (m[0].length === 0) {
        f.re.lastIndex++;
        continue;
      }
      if (body && m.index >= body.start && m.index < body.end) continue;
      hits.push({ form: f.id, label: f.label, index: m.index, line: lineAt(code, m.index), text: lineTextAt(code, m.index) });
    }
  }
  return hits;
}

/** 判定器 B（纯函数）：dedupSize 本体的四条形态，返回问题清单（0 = 口径完整）。 */
function judgeDedupShape(bodyText) {
  const problems = [];
  if (!/overlapsWith/.test(bodyText)) {
    problems.push('S1 未引用 overlapsWith —— 后端配对整条丢失，汇总退回逐条相加（界面总量虚高）');
  }
  if (!/-=\s*sizeNumber\s*\(/.test(bodyText)) {
    problems.push('S2 扣减没走 sizeNumber —— 扣的是未收敛的原始值（字符串/NaN 会把合计算崩）');
  }
  if (!/\.has\(\s*[A-Za-z_$][\w$]*\.[\w$]+\s*\)/.test(bodyText)) {
    problems.push('S3 缺「两端都在本次求和集合内」的 membership 门 —— 无条件扣减会把只勾父条的可清量报小');
  }
  if (!/>\s*0\s*\?|Math\.max\(\s*0\s*,|<\s*0\s*\?\s*0/.test(bodyText)) {
    problems.push('S4 缺非负兜底 —— 配对重复扣时界面出现负体积');
  }
  return problems;
}

/** 判定器 C（纯函数）：dedupSize 调用点计数（剔除声明自身，注释已在 code 层剥掉）。 */
function judgeCallSites(code) {
  const body = findDedupBody(code);
  const sites = [];
  for (const m of code.matchAll(/\bdedupSize\s*\(/g)) {
    if (body && m.index >= body.declIndex && m.index < body.declEnd) continue;
    if (/function\s+$/.test(code.slice(Math.max(0, m.index - 16), m.index))) continue;
    sites.push(lineAt(code, m.index));
  }
  return sites;
}

// ==================== 判定器自检（POSITIVE_CONTROLS）====================
// 每次运行都跑（不只 --self-test）：对照块坏了没人红，正是 T1b-M02 点名的滞留形态。
const AGG_CONTROLS = [
  // ① 违例形态：逐条断言命中数，命中数不符即红（不是「打印红」）
  { label: 'F1 违例：条目体积进 reduce', want: 1, code: 'const total = items.reduce((s, i) => s + sizeNumber(i.size), 0);\n' },
  { label: 'F2 违例：sizeNumber 映射后紧跟 reduce 相加', want: 1, code: 'const total = items.map(i => sizeNumber(i.size)).reduce((a, b) => a + b, 0);\n' },
  { label: 'F3 违例：体外 += 条目体积', want: 1, code: 'let acc = 0;\nfor (const i of items) acc += sizeNumber(i.size);\n' },
  { label: 'F3b 违例：体外 x = x + 条目体积', want: 1, code: 'let acc = 0;\nfor (const i of items) acc = acc + sizeNumber(i.size);\n' },
  { label: 'F4 违例：两条体积直接相加后写进 Map', want: 1, code: 'totals.set(gk, sizeNumber(totals.get(gk)) + sizeNumber(r.size));\n' },
  { label: '多形态同页：命中数要报准，不能只报第一条', want: 2, code: 'let acc = 0;\nfor (const i of items) acc += sizeNumber(i.size);\nconst total = picked.reduce((s, i) => s + sizeNumber(i.size), 0);\n' },
  // ② 合规形态：必须 0 命中（防判据退化成「永远红」）
  { label: '合规：走 dedupSize 的唯一汇总', want: 0, code: 'const total = dedupSize(items.map(i => i.id));\n' },
  { label: '合规：dedupSize 体内的 += 是口径实现，不算绕过面', want: 0, code: 'function dedupSize(ids) {\n  const set = new Set(ids);\n  let total = 0;\n  for (const id of set) total += sizeNumber(scanResults.get(id)?.size);\n  for (const id of set) for (const o of scanResults.get(id)?.overlapsWith || []) if (set.has(o.with)) total -= sizeNumber(o.bytes);\n  return total > 0 ? total : 0;\n}\n' },
  { label: '合规：计数类 reduce（sg.items.length）不得误伤', want: 0, code: 'const totalItems = subGroups.reduce((s, sg) => s + sg.items.length, 0);\n' },
  { label: '合规：注释里写出违例形态不算语料', want: 0, code: '// 别再写 totalFreed: allItems.reduce((s, i) => s + sizeNumber(i.size), 0)\nconst total = dedupSize(ids);\n' },
  { label: '合规：模板串插值里的累加照样被抓（洗字符串会漏判）→ 违例 1', want: 1, code: 'const html = `<b>${items.reduce((s, i) => s + sizeNumber(i.size), 0)}</b>`;\n' },
  { label: '正则字面量的字符类不得让扫描器原地打转（真挂过：字符类分支漏推进）', want: 1, code: 'const re = /["\'`]/g; /* 块注释里的 reduce((s, i) => s + sizeNumber(i.size), 0) 不算语料 */\nconst bad = items.reduce((s, i) => s + sizeNumber(i.size), 0);\n' },
];
const SHAPE_CONTROLS = [
  {
    label: '合规本体：四条形态齐备',
    want: 0,
    body: '{ const set = new Set(ids); let total = 0;\n  for (const id of set) total += sizeNumber(scanResults.get(id)?.size);\n  for (const id of set) for (const o of scanResults.get(id)?.overlapsWith || []) if (set.has(o.with)) total -= sizeNumber(o.bytes);\n  return total > 0 ? total : 0; }',
  },
  {
    label: 'S1+S2+S3 同灭：退回纯相加',
    want: 3,
    body: '{ const set = new Set(ids); let total = 0;\n  for (const id of set) total += sizeNumber(scanResults.get(id)?.size);\n  return total > 0 ? total : 0; }',
  },
  {
    label: 'S3 被摘：无条件扣减（只勾父条也扣 → 可清量报小）',
    want: 1,
    body: '{ const set = new Set(ids); let total = 0;\n  for (const id of set) total += sizeNumber(scanResults.get(id)?.size);\n  for (const id of set) for (const o of scanResults.get(id)?.overlapsWith || []) total -= sizeNumber(o.bytes);\n  return total > 0 ? total : 0; }',
  },
  {
    label: 'S2 被摘：扣减绕过 sizeNumber 收敛',
    want: 1,
    body: '{ const set = new Set(ids); let total = 0;\n  for (const id of set) total += sizeNumber(scanResults.get(id)?.size);\n  for (const id of set) for (const o of scanResults.get(id)?.overlapsWith || []) if (set.has(o.with)) total -= o.bytes;\n  return total > 0 ? total : 0; }',
  },
  {
    label: 'S4 被摘：无非负兜底',
    want: 1,
    body: '{ const set = new Set(ids); let total = 0;\n  for (const id of set) total += sizeNumber(scanResults.get(id)?.size);\n  for (const id of set) for (const o of scanResults.get(id)?.overlapsWith || []) if (set.has(o.with)) total -= sizeNumber(o.bytes);\n  return total; }',
  },
];

function runControls() {
  let bad = 0;
  for (const c of AGG_CONTROLS) {
    const got = judgeAggregates(mask(c.code).code).length;
    if (got !== c.want) {
      bad++;
      g.fail(`正向对照失败：「${c.label}」期望命中 ${c.want} 处、实测 ${got} 处 —— 判定器退化（恒绿或恒红），✓ 不可信`);
    }
  }
  for (const c of SHAPE_CONTROLS) {
    const got = judgeDedupShape(c.body).length;
    if (got !== c.want) {
      bad++;
      g.fail(`正向对照失败：本体判据「${c.label}」期望 ${c.want} 条问题、实测 ${got} 条 —— S1~S4 判据与样本口径不一致`);
    }
  }
  // 调用点计数与本体解析的方向对照：恒绿（解析不出）与恒红（将声明计入）都要被判据自己抓到
  const fourCalls = judgeCallSites(mask('dedupSize(a);\ndedupSize(b);\ndedupSize(c);\ndedupSize(d);\n').code).length;
  const declNotCall = judgeCallSites(mask('function dedupSize(ids) { return 0; }\n').code).length;
  const noBody = findDedupBody(mask('const total = dedupSize(ids);\n').struct);
  if (fourCalls !== 4 || declNotCall !== 0 || noBody !== null) {
    bad++;
    g.fail(`正向对照失败：调用点计数/本体解析退化（4 调用实测 ${fourCalls}、声明自身实测 ${declNotCall}、无本体实测 ${noBody === null ? 'null' : '解析成功'}）`);
  }
  if (bad === 0) {
    g.ok(`判定器自检：${AGG_CONTROLS.length} 条累加形态样本 + ${SHAPE_CONTROLS.length} 条本体形态样本 + 3 条计数/解析对照，违例全命中、合规 0 命中`);
  }
  return bad;
}

const g = gate(import.meta.url);
console.log('=== 磁盘清理页体积汇总单一口径（dedupSize）门禁 ===\n');

if (SELF_TEST_ONLY) {
  const bad = runControls();
  g.finish(bad === 0 ? 'check-cleanup-aggregates --self-test: 判定器自检全部通过' : undefined);
  process.exit(g.failed > 0 ? 1 : 0);
}

const targetAbs = FILE_ARG ? resolve(FILE_ARG) : TARGET;
// 取证通道的目标在仓外时不打相对路径（`../../Users/...` 那种输出没法读），原样回显入参
const targetLabel = FILE_ARG
  ? (relative(ROOT, targetAbs).startsWith('..') ? FILE_ARG : relative(ROOT, targetAbs).replace(/\\/g, '/'))
  : TARGET_REL;
if (!existsSync(targetAbs)) {
  // src/scripts/cleanup.js 是跟踪文件：干净克隆里必须在，缺失即真问题（不是 SKIP）
  g.fail(`${targetLabel} 不在 —— 判定面对象失踪，本门禁无从对拍（不是「没有违规」）`);
  g.finish();
  process.exit(1);
}

const raw = readFileSync(targetAbs, 'utf8');
const { code, struct } = mask(raw);

// ── 1. 扫描面地板：先确认判定面还活着，再谈「零违规」 ──
const sizeNumberCount = (code.match(/\bsizeNumber\s*\(/g) || []).length;
if (sizeNumberCount < SIZE_NUMBER_FLOOR) {
  g.fail(`扫描面地板：${targetLabel} 只解析到 ${sizeNumberCount} 处 sizeNumber(（地板 ${SIZE_NUMBER_FLOOR}）—— 文件被换/函数改名后「零违规」是假的`);
} else {
  g.ok(`扫描面地板：页内 sizeNumber( 现算 ${sizeNumberCount} 处 ≥ ${SIZE_NUMBER_FLOOR}，判定面活着`);
}

// ── 2. dedupSize 本体在位 + 四条形态判据 ──
const body = findDedupBody(struct);
if (!body) {
  g.fail(`${targetLabel} 解析不到 dedupSize 函数体（改名/删除/写成无大括号箭头体都会到这里）—— 豁免域与扣减判据同时失明，判红而不是放行`);
} else {
  const bodyText = code.slice(body.start, body.end);
  const shapeProblems = judgeDedupShape(bodyText);
  if (shapeProblems.length > 0) {
    for (const p of shapeProblems) g.fail(`dedupSize 本体（第 ${body.start} 字符起）形态不完整：${p}`);
  } else {
    g.ok(`dedupSize 本体四条形态齐备（S1 引用 overlapsWith / S2 扣减走 sizeNumber / S3 两端都在集合内的门 / S4 非负兜底）`);
  }
}

// ── 3. 调用点地板：口径真的在被用，而不是只写着好看 ──
const sites = judgeCallSites(code);
if (sites.length < CALL_FLOOR) {
  g.fail(`dedupSize 调用点只剩 ${sites.length} 处（地板 ${CALL_FLOOR}，行号 ${sites.join('/')}）—— 汇总退回别处实现即虚高回归`);
} else {
  g.ok(`dedupSize 调用点现算 ${sites.length} 处 ≥ ${CALL_FLOOR}（行 ${sites.join(' / ')}）`);
}

// ── 4. 累加形态扫描 + 豁免台账双向咬合 ──
const hits = judgeAggregates(code);
const usedExempts = new Map();
const unregistered = [];
for (const h of hits) {
  const ex = EXEMPTS.find((e) => e.form === h.form && h.text.includes(e.anchor));
  if (ex) {
    usedExempts.set(ex.anchor, (usedExempts.get(ex.anchor) || 0) + 1);
  } else {
    unregistered.push(`[${h.form} ${h.label}] ${targetLabel}:${h.line}  ${h.text}`);
  }
}
if (unregistered.length > 0) {
  for (const v of unregistered) g.fail(`体积汇总绕过 dedupSize（未登记）：${v}`);
} else if (hits.length > 0) {
  g.warn(`累加形态命中 ${hits.length} 处，全部落在已登记豁免内（各按 file+锚点认领，命中 0 处即红）`);
} else {
  g.ok('累加形态扫描：F1/F2/F3/F3b/F4 零命中，页内体积汇总只走 dedupSize 一处口径');
}
// 豁免台账双向咬合：登记不命中 = 白名单腐烂；锚点命中多处 = 失去判别力（§5.19）
const registryProblems = [];
for (const e of EXEMPTS) {
  const occurrences = code.split(e.anchor).length - 1;
  if (occurrences !== 1) {
    registryProblems.push(`锚点「${e.anchor}」在 ${targetLabel} 命中 ${occurrences} 处（应恰好 1 处；0 = 形态已改掉、豁免该删，≥2 = 锚点不判别）`);
  } else if (!usedExempts.has(e.anchor)) {
    registryProblems.push(`锚点「${e.anchor}」在盘上但没认领任何命中 —— 该形态的判据被摘掉了，请复核判定器`);
  }
}
if (registryProblems.length > 0) {
  for (const p of registryProblems) g.fail(`豁免台账腐烂（正向对照判红）：${p}`);
} else {
  g.ok(`豁免台账 ${EXEMPTS.length} 条各命中 1 处并各认领一条违规（登记不命中即红）`);
}

runControls();

g.finish('check-cleanup-aggregates: 全部通过');
