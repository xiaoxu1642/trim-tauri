'use strict';
// check-escape-delegation.mjs —— 转义/字节格式化「唯一真源 + 只许委托」门禁
//
// 出处：审查 L3 2026-10-01 NEW-3；2026-11-01 全仓重审「门禁假绿 #6」（F1b）：
// 旧判据的定义名白名单只认 escapeHtml|escapeAttr，报告里的合成样本多数 0 命中
// （`function esc(`、`escAttr`、`htmlEscape`、`formatSize`、`fmtBytes` 箭头形、
// `formatBytes`、`fmtSpeed` 全部在射程外）——把真实薄包装改成重实现不会变红。
//
// 本门禁现在断言三件事（任一独立判红）：
//   A. 定义面：真实转义/字节格式化名集合（见 ESC_NAMES / BYTE_NAMES，2026-11-02 现算
//      `rg -n 'function\s+(esc|escAttr|escapeHtml|escapeAttr)' src/scripts` 等四条命令回填，
//      非照抄报告）的每一种定义形态（函数声明 / 箭头 / 函数表达式 / 别名）必须**纯委托**
//      `window.ds.esc / escAttr / fmtBytes / fmtRate`；ds.js 是唯一真源，只验活性不判委托。
//   B. 行为面（名字无关）：函数体里出现实体表重实现（`ESC_MAP =`、`replace` 实体字面量、
//      字符类 `/[&<>"']/`）或字节格式化重实现（`toFixed` + `B/KB/MB/GB/TB` 单位，或
//      1024/1000 换算）→ 判红。名字可以改，行为签名改不掉。
//   C. 汇聚面：HTML sink（innerHTML / outerHTML / insertAdjacentHTML）的 `+` 拼接与模板
//      直接插值里，出现**不能证明已转义**的裸标识符/成员访问 → 判红（「未委托的字符串
//      拼接进 HTML」）。可证安全的放行：数值（Number/Math/算术/.length/.size/计数类成员）、
//      上游已委托（声明首表达式含 ds.esc/escAttr）、字符串字面量片段、HTML 槽位
//      （*Html/*Svg/*Class/icon/dataset/id）、map(...).join(...) 构建器。
//      已知边界：直接调用视为被调方负责（其模板定义处在同一扫描面）；字段级污点需要
//      类型信息，本门禁只拦「整段裸值/裸字段拼进 HTML」，不做跨语句污点传播。
//      不能证明的现存项按 file#fn#操作数逐条登记进 TRANSITION（只减不增，台账条目必须
//      命中，代码修好而台账不回收同样判红）。
//
// 完全收敛（删包装、调用点直用 window.ds.*）仍是渐进目标：触到哪个文件顺手改哪个，
// 改完把 BASELINE 相应下调即可（下调无需审批，上调即红）。
//
// 破坏自证（2026-11-02 实跑）：在 modal.js 末尾临时加一句未转义的 `+` 拼接，
// 本门禁退出 1 并点名 modal.js 的裸操作数；删掉即恢复 exit 0（见回执）。
//
// 用法：node tools/check-escape-delegation.mjs

import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkFiles } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, lineAt } from './lib/src-scan.mjs';

const g = gate(import.meta.url);
const DIR = join(REPO_ROOT, 'src', 'scripts');
const TRUTH_SOURCE = 'ds.js';

// ---- 真实名单（2026-11-02 现算；见文件头命令）----
// 转义族：esc / escAttr（src/scripts/finder.js:113、src/scripts/uninstall.js:26、src/scripts/residue-window.js:17 等）
//          escapeHtml / escapeAttr（大量历史薄包装）
//          escHtml / htmlEscape / escapeHTML（同义别名，报告样本里出现过，纳入射程）
const ESC_NAMES = ['esc', 'escAttr', 'escapeHtml', 'escapeAttr', 'escHtml', 'htmlEscape', 'escapeHTML'];
// 字节/速率族（现盘真实在用）：fmtBytes / formatSize（cleanup、finder 等）、
// fmtSizeKb（src/scripts/uninstall.js:28）、fmtSpeed（src/scripts/netspeed.js:67）、formatSpeed（src/scripts/realtime.js:90）、
// formatBlock（src/scripts/diskbench.js:169）；fmtRate 是 ds.js 真源；formatBytes / formatRate 为同义别名。
const BYTE_NAMES = ['fmtBytes', 'formatBytes', 'formatSize', 'fmtRate', 'formatRate', 'fmtSpeed', 'fmtSizeKb', 'formatSpeed', 'formatBlock'];
const ALL_NAMES = [...ESC_NAMES, ...BYTE_NAMES];

// 定义总数地板（2026-11-02 现算回填；只许下调）。
// 旧基线 30 只覆盖 escapeHtml/escapeAttr；扩名后必须重算，不能沿用旧数冒充收紧。
const BASELINE_ESC = 34;
const BASELINE_BYTE = 10;

/** 该名字应委托到哪个真源函数 */
function expectedDelegate(name) {
  if (/attr/i.test(name)) return 'escAttr';
  if (/rate|speed/i.test(name)) return 'fmtRate';
  if (/bytes|size|block/i.test(name)) return 'fmtBytes';
  return 'esc';
}

const NAME_ALT = ALL_NAMES.join('|');
// 函数声明 / 函数表达式 / 箭头 / 纯别名（`const esc = window.ds.esc;`）四种形态。
// 体不跨 `}`：本地包装都是薄函数（与旧判据同口径）；跨 `}` 的重实现由 B 段行为签名兜住。
const RE_DEF_FN = new RegExp(`function\\s+(${NAME_ALT})\\s*\\([^)]*\\)\\s*\\{([^}]*)\\}`, 'g');
const RE_DEF_FNEXPR = new RegExp(`(?:const|let|var)\\s+(${NAME_ALT})\\s*=\\s*function\\s*\\([^)]*\\)\\s*\\{([^}]*)\\}`, 'g');
const RE_DEF_ARROW = new RegExp(`(?:const|let|var)\\s+(${NAME_ALT})\\s*=\\s*(?:\\([^)]*\\)|[\\w$]+)\\s*=>\\s*([^;\\n]+)`, 'g');
const RE_DEF_ALIAS = new RegExp(`(?:const|let|var)\\s+(${NAME_ALT})\\s*=\\s*window\\.ds\\.(esc|escAttr|fmtBytes|fmtRate)\\s*;`, 'g');

const delegated = (name, body) => new RegExp(`window\\.ds\\.${expectedDelegate(name)}\\b`).test(body);

/** 去掉最外层配对括号（可能嵌套） */
function unwrapParens(e) {
  let s = e.trim();
  while (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0, wraps = true;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '(') depth++;
      else if (s[i] === ')') { depth--; if (depth === 0 && i !== s.length - 1) { wraps = false; break; } }
    }
    if (!wraps) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

/** 跳过字符串/模板/正则字面量，返回结束下标（i 指向字面量起点） */
function skipLiteral(text, i) {
  const c = text[i];
  if (c === '"' || c === "'") {
    i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i] === c) return i + 1;
      if (text[i] === '\n') return i;
      i++;
    }
    return i;
  }
  if (c === '`') {
    i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i] === '$' && text[i + 1] === '{') { i = skipBraces(text, i + 1); continue; }
      if (text[i] === '`') return i + 1;
      i++;
    }
    return i;
  }
  return i;
}

/** 从 `{` 起配平（含字符串/模板跳过），返回闭合后的下标 */
function skipBraces(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') { i = skipLiteral(text, i) - 1; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return i + 1; }
  }
  return text.length;
}

/** 读一条表达式：字面量/括号配平，顶层 `;`（或逗号）收口 */
function readExpr(text, start, stopComma = false) {
  let i = start, depth = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') { i = skipLiteral(text, i); continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; i++; continue; }
    if (c === ')' || c === ']' || c === '}') { if (depth === 0) break; depth--; i++; continue; }
    if (depth === 0 && c === ';') break;
    if (depth === 0 && stopComma && c === ',') break;
    i++;
  }
  return text.slice(start, i);
}

/** 顶层按分隔符切（支持多字符分隔，跳过字面量与括号） */
function splitTop(expr, sep) {
  const parts = [];
  let cur = '', i = 0, depth = 0;
  while (i < expr.length) {
    const c = expr[i];
    if (c === '"' || c === "'" || c === '`') {
      const j = skipLiteral(expr, i);
      cur += expr.slice(i, j); i = j; continue;
    }
    if (c === '(' || c === '[' || c === '{') { depth++; cur += c; i++; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; cur += c; i++; continue; }
    if (depth === 0 && expr.startsWith(sep, i)) {
      // 单字符 `+` 不切 `++`，`-` 不切 `->`
      if (sep === '+' && (expr[i + 1] === '+' || expr[i - 1] === '+')) { cur += c; i++; continue; }
      parts.push(cur.trim()); cur = ''; i += sep.length; continue;
    }
    cur += c; i++;
  }
  if (cur.trim() || parts.length) parts.push(cur.trim());
  return parts.filter((p) => p.length);
}

/** 模板字面量的直接 `${}` 插值（不进入嵌套模板/嵌套表达式里的模板） */
function directInterps(tpl) {
  const out = [];
  let i = 1;
  while (i < tpl.length - 1) {
    if (tpl[i] === '\\') { i += 2; continue; }
    if (tpl[i] === '$' && tpl[i + 1] === '{') {
      const end = skipBraces(tpl, i + 1);
      out.push(tpl.slice(i + 2, end - 1).trim());
      i = end;
      continue;
    }
    i++;
  }
  return out;
}

/** 顶层三元：返回 [真分支, 假分支]；没有则 null */
function splitTernary(expr) {
  let i = 0, depth = 0, q = -1;
  while (i < expr.length) {
    const c = expr[i];
    if (c === '"' || c === "'" || c === '`') { i = skipLiteral(expr, i); continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; i++; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; i++; continue; }
    if (depth === 0 && c === '?' && expr[i + 1] !== '?' && expr[i + 1] !== '.' && expr[i - 1] !== '?') {
      q = i; break;
    }
    i++;
  }
  if (q < 0) return null;
  let j = q + 1, d = 0;
  while (j < expr.length) {
    const c = expr[j];
    if (c === '"' || c === "'" || c === '`') { j = skipLiteral(expr, j); continue; }
    if (c === '(' || c === '[' || c === '{') { d++; j++; continue; }
    if (c === ')' || c === ']' || c === '}') { d--; j++; continue; }
    if (d === 0 && c === ':') return [expr.slice(q + 1, j).trim(), expr.slice(j + 1).trim()];
    j++;
  }
  return null;
}

const ESC_CALL = /^(?:window\s*\.\s*)?(?:(?:ds)\s*\.\s*)?(?:esc|escAttr|escapeHtml|escapeAttr|escHtml|htmlEscape|escapeHTML)\s*\(/;
const NUMERIC_CALL = /^(?:Number|parseInt|parseFloat|Math\s*\.\s*\w+|Date\s*\.\s*now)\s*\(/;
const IDENT_MEMBER = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[[^\]]*\])*$/;
const CALL_START = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[[^\]]*\])*\s*\(/;

/** 括号深度表（code 已抹字符串，花括号只可能来自代码） */
function depthMap(code) {
  const depth = new Int32Array(code.length + 1);
  let d = 0;
  for (let i = 0; i < code.length; i++) {
    depth[i] = d;
    if (code[i] === '{') d++;
    else if (code[i] === '}') d = Math.max(0, d - 1);
  }
  depth[code.length] = d;
  return depth;
}

/** 声明是否与 sink 同作用域：声明之后、sink 之前不得掉回更浅的花括号深度（跨函数/跨块声明不算数） */
function sameScope(pos, offset, depth) {
  if (!depth || pos >= offset) return false;
  const base = depth[pos];
  for (let i = pos + 1; i <= offset; i++) if (depth[i] < base) return false;
  return true;
}

/** 在文件里找 name 的最近一次 `const/let/var name =` 初始化（同作用域、且位于 sink 之前） */
function findDecl(ctx, name) {
  const re = new RegExp(`\\b(?:const|let|var)\\s+${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*`, 'g');
  let best = null, m;
  while ((m = re.exec(ctx.text)) !== null) {
    if (ctx.offset == null || m.index >= ctx.offset) break;
    if (sameScope(m.index, ctx.offset, ctx.depth)) best = m.index + m[0].length;
  }
  if (best == null) return null;
  return readExpr(ctx.text, best).trim();
}

/** 数值语义的成员名（计数/体积/时长/百分比；仓内 IPC 回执的既有命名口径） */
const NUMERIC_MEMBER = /\.\w*(?:count|total|size|length|bytes|pid|index|percent|ratio|ms|kb)$/i;

/** 数值表达式：字面量 / Number,Math / .length,.size / 顶层四则运算，原子递归到声明 */
function isNumericExpr(ctx, expr, depth = 0) {
  const e = unwrapParens(expr);
  if (!e || depth > 5) return false;
  if (/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(e)) return true;
  if (/\.(?:length|size)\b/.test(e) && !/\.(?:length|size)\b[^+\-*/%]*\?/.test(e)) return true;
  if (/^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+$/.test(e) && NUMERIC_MEMBER.test(e)) return true;
  if (NUMERIC_CALL.test(e)) return true;
  if (/^(?:null|undefined)$/.test(e)) return false;
  const atoms = splitTop(e, '+').flatMap((p) => splitTop(p, '-')).flatMap((p) => splitTop(p, '*')).flatMap((p) => splitTop(p, '/')).flatMap((p) => splitTop(p, '%'));
  if (atoms.length > 1) return atoms.every((a) => isNumericExpr(ctx, a, depth + 1));
  if (/^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)?$/.test(e)) {
    const init = findDecl(ctx, e.split(/\??\./)[0]);
    if (init != null) return isNumericExpr(ctx, init, depth + 1);
  }
  return false;
}

/** 声明片段：`x.map(...).join(...)` 是仓内通用构建器；其模板在函数体内另有定义处，本门禁不重复判 */
const builderFragment = (init) => /\.(?:map|flatMap)\s*\(/.test(init) && /\.join\s*\(/.test(init);

/** 解析一个 HTML 拼接操作数/插值；false = 不能证明已转义 */
function analyzeOperand(ctx, expr, depth = 0) {
  const e = unwrapParens(expr);
  if (!e || depth > 6) return true; // 空/过深不制造红；对象地板与对照负责判据失效
  if (/^(?:null|undefined|true|false)$/.test(e)) return true;
  if (/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(e)) return true;
  if (/^["']/.test(e)) return true; // 字符串字面量（代码作者写的片段）
  if (ESC_CALL.test(e)) return true; // 调用委托
  if (isNumericExpr(ctx, e)) return true; // 数值/计数/几何：无字符串注入面
  if (e.startsWith('`')) return directInterps(e).every((x) => analyzeOperand(ctx, x, depth + 1));
  if (splitTop(e, '+').length > 1) return splitTop(e, '+').every((x) => analyzeOperand(ctx, x, depth + 1));
  const tern = splitTernary(e);
  if (tern) return analyzeOperand(ctx, tern[0], depth + 1) && analyzeOperand(ctx, tern[1], depth + 1);
  for (const op of ['||', '??', '&&']) {
    const parts = splitTop(e, op);
    if (parts.length > 1) return parts.every((x) => analyzeOperand(ctx, x, depth + 1));
  }
  if (CALL_START.test(e)) return true; // 直接调用：被调方负责（其模板定义处在同一扫描面）
  if (!IDENT_MEMBER.test(e)) return false; // 不认识的拼接形态：安全侧判红
  // 成员访问：数值属性、常量表成员、UI 槽位（*Html/*Svg/*Class/icon/dataset/id）放行；
  // 其余成员在本门禁无法证明类型，按 file#fn#操作数登记过渡（安全侧，不放行）。
  if (/\??\.|\[/.test(e)) {
    if (NUMERIC_MEMBER.test(e)) return true;
    if (/\.\w*(?:Html|HTML|Svg|SVG|Class|class|icon|Icon)$/.test(e)) return true;
    if (/\.(?:dataset|textContent|innerHTML|id)\b/.test(e)) return true;
    const base = /^[A-Za-z_$][\w$]*/.exec(e)[0];
    const init = findDecl(ctx, base);
    if (init != null && /^[{[]/.test(init.trim())) return true; // 常量表
    return false;
  }
  const init = findDecl(ctx, e);
  if (init == null) return false; // 参数 / 全局：裸数据
  if (isNumericExpr(ctx, init)) return true;
  if (builderFragment(init)) return true;
  return analyzeOperand(ctx, init, depth + 1);
}

/** 找到包含偏移的最内层函数名（用于过渡表 file#fn） */
function enclosingFn(rawText, offset) {
  let best = null;
  for (const f of splitFunctions(rawText, 'js')) {
    if (offset >= f.start && offset < f.end && (!best || f.end - f.start < best.end - best.start)) best = f;
  }
  return best && best.name && best.name !== '(匿名)' ? best.name : '(匿名)';
}

/** 把 HTML sink 表达式拆成叶子（模板直接插值 / `+` 操作数 / 三元两分支） */
function htmlLeaves(expr, out = []) {
  const e = unwrapParens(expr);
  if (!e) return out;
  if (e.startsWith('`')) {
    for (const x of directInterps(e)) htmlLeaves(x, out);
    return out;
  }
  const tern = splitTernary(e);
  if (tern) {
    htmlLeaves(tern[0], out);
    htmlLeaves(tern[1], out);
    return out;
  }
  const plus = splitTop(e, '+');
  if (plus.length > 1) {
    for (const p of plus) htmlLeaves(p, out);
    return out;
  }
  out.push(e);
  return out;
}

// 过渡表：收紧后的现存违例逐条登记（file#fn#操作数），只减不增。
// 2026-11-02 收紧后现算两条（全仓 HTML 汇聚点全扫，无整文件跳过）：
//   · cleanup.js#openItemDetail#total —— resp.data 解构出的注册表条目计数（后端契约为
//     number，只作文本展示）；门禁不解析解构类型 ⇒ 登记放行。收敛方向：Number(total)
//     显式化，或走 ds 的数字格式化。
//   · optimizer.js#renderGroups#moreBtn —— map 回调内的字面量按钮片段（三元两支均为
//     字符串字面量，无插值）；声明在 sink 起点之后，门禁不进入回调体取声明 ⇒ 登记放行。
//     收敛方向：内联进模板或提到 sink 之前。
// 表机制：新增违例要么改代码，要么在此逐条登记并写明理由；条目必须命中，
// 代码修好而台账不回收同样判红（双向咬合，防「登记后永远绿」）。
const TRANSITION = [
  { file: 'cleanup.js', fn: 'openItemDetail', operand: 'total', count: 1, why: 'resp.data 解构计数（number 契约）；门禁不解析解构类型' },
  { file: 'optimizer.js', fn: 'renderGroups', operand: 'moreBtn', count: 1, why: 'map 回调内字面量按钮片段（无插值）；声明在 sink 起点之后' },
];

function run(sources) {
  const out = {
    files: sources.length,
    escapeDefs: 0,
    byteDefs: 0,
    forms: { fn: 0, arrow: 0, fnexpr: 0, alias: 0 },
    badForm: [],
    badBehavior: [],
    sinkSites: 0,
    sinkViolations: [], // { file, line, fn, operand, count }
  };
  const truth = sources.find((s) => s.rel === TRUTH_SOURCE);
  if (truth) {
    const live = blankNonCode(truth.text, 'js', { keepStrings: true });
    const entities = ['&amp;', '&lt;', '&gt;', '&quot;', '&#39;'];
    if (!/function\s+esc\s*\(/.test(live) || !/function\s+escAttr\s*\(/.test(live)
      || !/function\s+fmtBytes\s*\(/.test(live) || !/function\s+fmtRate\s*\(/.test(live)
      || !/replace\s*\(\s*\/\[&<>"'\]\/g/.test(live)
      || !entities.every((x) => live.includes(x))) {
      out.badBehavior.push(`${TRUTH_SOURCE}:? 真源本体失活（esc/escAttr/fmtBytes/fmtRate 或 ESC_MAP 五实体缺失）`);
    }
  }

  const violationMap = new Map();
  for (const src of sources) {
    const code = blankNonCode(src.text, 'js'); // 注释+字符串抹白：委托调用只能来自代码
    const live = blankNonCode(src.text, 'js', { keepStrings: true }); // 注释抹白：字符串/正则保留

    // ---- A. 定义面 ----
    if (src.rel !== TRUTH_SOURCE) {
      const take = (re, label) => {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(code)) !== null) {
          if (BYTE_NAMES.includes(m[1])) out.byteDefs++;
          else out.escapeDefs++;
          out.forms[label]++;
        }
      };
      take(RE_DEF_FN, 'fn');
      take(RE_DEF_FNEXPR, 'fnexpr');
      take(RE_DEF_ARROW, 'arrow');
      take(RE_DEF_ALIAS, 'alias');
      // 逐个形态判委托（与计数同源，但需要 body 分组）
      for (const [re, label] of [[RE_DEF_FNEXPR, 'fnexpr'], [RE_DEF_FN, 'fn'], [RE_DEF_ARROW, 'arrow']]) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(code)) !== null) {
          const key = `${src.rel}:${lineAt(code, m.index)} ${m[1]}（${label}）`;
          if (!delegated(m[1], m[2] || '')) {
            if (!out.badForm.includes(key)) out.badForm.push(key);
          }
        }
      }
      RE_DEF_ALIAS.lastIndex = 0;
      let m;
      while ((m = RE_DEF_ALIAS.exec(code)) !== null) {
        if (m[2] !== expectedDelegate(m[1])) {
          out.badForm.push(`${src.rel}:${lineAt(code, m.index)} ${m[1]}（别名委托到 ${m[2]}，应为 ${expectedDelegate(m[1])}）`);
        }
      }
    }

    // ---- B. 行为面（名字无关）----
    if (src.rel !== TRUTH_SOURCE) {
      if (/ESC_MAP\s*=/.test(code)) out.badBehavior.push(`${src.rel}: ESC_MAP 第二张转义表`);
      // 实体替换：① 字符类里同时含 & 与 < >；② replace 的实参/替换串出现实体字面量。
      // 只认「实体实现」形态，不认 markdown 里 `<h1>`/`>` 这类普通正则（src/scripts/app.js:653 曾假红）。
      const entityImpl = (body) =>
        /(?:replace|replaceAll)\s*\(\s*\/\[[^\]\n]*&[^\]\n]*[<>]/.test(body)
        || /(?:replace|replaceAll)\s*\([^\n]{0,200}(?:&amp;|&lt;|&gt;|&quot;|&#39;)/.test(body);
      const byteImpl = (name, body) => {
        const nameHits = /(?:fmt|format|bytes|size|rate|speed)/i.test(name);
        const byteMath = /\b(?:1024|1000)\b/.test(body);
        const unit = /["'`]\s*(?:B|KB|MB|GB|TB)(?:\s*\/\s*s)?\s*["'`]/.test(body);
        return (nameHits || byteMath) && /toFixed\s*\(/.test(body) && unit;
      };
      const fns = splitFunctions(src.text, 'js');
      for (const f of fns) {
        const body = live.slice(f.bodyStart, f.end);
        if (entityImpl(body)) out.badBehavior.push(`${src.rel}:${f.sigLine} ${f.name}() 自行实现转义`);
        if (byteImpl(f.name, body)) out.badBehavior.push(`${src.rel}:${f.sigLine} ${f.name}() 自行实现字节格式化`);
      }
      // 表达式体箭头（`const fmtBytes = (b) => ...`）splitFunctions 切不到体，这里按定义扫描补一层
      const arrowRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\([^)]*\)|[\w$]+)\s*=>\s*([^\n]+)/g;
      let am;
      while ((am = arrowRe.exec(live)) !== null) {
        if (entityImpl(am[2])) out.badBehavior.push(`${src.rel}:${lineAt(live, am.index)} ${am[1]}() 自行实现转义（箭头）`);
        if (byteImpl(am[1], am[2])) out.badBehavior.push(`${src.rel}:${lineAt(live, am.index)} ${am[1]}() 自行实现字节格式化（箭头）`);
      }
    }

    // ---- C. 汇聚面 ----
    // 汇聚点定位在 code（字符串已抹白）上，表达式从 live（字符串/模板保留）里读——
    // 字符串里出现的 "innerHTML" 字样不算汇聚点。
    const ctx = { text: live, offset: 0, depth: depthMap(code) };
    // 注意：正则**不能**在 `=` 后带 `\s*` —— code 里模板/字符串被抹成空格，
    // `\s*` 会把整段 RHS 吃掉，start 漂到表达式末尾（2026-11-02 实测）。
    const sinkRe = /\.(?:innerHTML|outerHTML)\s*(?:\+?=)/g;
    let sm;
    while ((sm = sinkRe.exec(code)) !== null) {
      out.sinkSites++;
      ctx.offset = sm.index;
      collectSink(readExpr(live, sm.index + sm[0].length), sm.index);
    }
    const insRe = /\binsertAdjacentHTML\s*\(/g;
    while ((sm = insRe.exec(code)) !== null) {
      out.sinkSites++;
      ctx.offset = sm.index;
      const argStart = sm.index + sm[0].length;
      const first = readExpr(live, argStart, true); // 首参 = 插入位置关键字
      let j = argStart + first.length;
      while (j < live.length && /\s/.test(live[j])) j++;
      if (live[j] === ',') j++;
      while (j < live.length && /\s/.test(live[j])) j++;
      collectSink(readExpr(live, j), sm.index); // 第二参 = HTML 正文
    }

    function collectSink(expr, at) {
      const line = lineAt(live, at);
      const fn = enclosingFn(src.text, at);
      for (const op of htmlLeaves(expr)) {
        if (analyzeOperand(ctx, op)) continue;
        const key = `${src.rel}#${fn}#${op.replace(/\s+/g, ' ').slice(0, 60)}`;
        const hit = violationMap.get(key) || { file: src.rel, line, fn, operand: op.replace(/\s+/g, ' ').slice(0, 60), count: 0 };
        hit.count++;
        violationMap.set(key, hit);
      }
    }
  }
  out.sinkViolations = [...violationMap.values()];
  return out;
}

// ---- 语料 ----
const files = walkFiles(DIR, (f) => f.endsWith('.js'))
  .map((p) => relative(DIR, p).replace(/\\/g, '/')).sort();
if (files.length === 0) {
  g.fail('src/scripts 下没有 .js 文件 ⇒ 扫描面失效（目录被搬/改名？），拒绝判绿');
  g.finish();
  process.exit(1);
}
const sources = files.map((rel) => ({ rel, text: readFileSync(join(DIR, rel), 'utf8') }));
const r = run(sources);

// ---- 地板 ----
if (r.escapeDefs === 0) g.fail('转义包装定义排查 0 条 ⇒ 判定正则或语料失效，不允许判绿');
if (r.forms.fn === 0) g.fail('函数声明形态 0 条 ⇒ RE_DEF_FN 失明');
if (r.forms.arrow === 0) g.fail('箭头定义形态 0 条 ⇒ RE_DEF_ARROW 失明');
if (r.byteDefs === 0) g.fail('字节格式化定义排查 0 条 ⇒ 名字集合或语料失效，不允许判绿');
if (r.sinkSites === 0) g.fail('HTML 汇聚点 0 处 ⇒ 汇聚面判定失明，不允许判绿');
if (!sources.some((s) => s.rel === TRUTH_SOURCE)) g.fail('ds.js 不在扫描面里 ⇒ 真源活性无法校验');

// ---- 汇总判定 ----
for (const b of r.badForm) g.fail(`${b} — 定义体不是 window.ds.* 纯委托（重实现会与真源字符集分叉）`);
for (const b of r.badBehavior) g.fail(`${b} — 行为签名命中自行实现（名字可改，行为判据不放行）`);

const declared = new Map(TRANSITION.map((t) => [`${t.file}#${t.fn}#${t.operand}`, t]));
for (const v of r.sinkViolations) {
  const key = `${v.file}#${v.fn}#${v.operand}`;
  const entry = declared.get(key);
  if (!entry) {
    g.fail(`${v.file}:${v.line} ${v.fn}() 把未委托的 ${v.operand} 拼进 HTML（出现 ${v.count} 次）——改为 ds.esc/escAttr 委托，或按纪律登记进 TRANSITION`);
    continue;
  }
  if (v.count > entry.count) {
    g.fail(`${v.file} ${v.fn}() ${v.operand} 命中 ${v.count} 次 > 过渡基线 ${entry.count}（只减不增）`);
  }
}
for (const [key, t] of declared) {
  const v = r.sinkViolations.find((x) => `${x.file}#${x.fn}#${x.operand}` === key);
  if (!v) g.fail(`过渡条目 ${key} 已不命中 ⇒ 台账失效（代码修好请回收该行，不许留长期豁免）`);
  else if (v.count < t.count) {
    g.warn(`过渡条目 ${key} 由 ${t.count} 降到 ${v.count}，可下调 count（不强制）`);
  }
}

const escOk = r.escapeDefs <= BASELINE_ESC;
const byteOk = r.byteDefs <= BASELINE_BYTE;
if (!escOk) g.fail(`转义包装定义 ${r.escapeDefs} > 基线 ${BASELINE_ESC}（只许递减，禁止新增）`);
if (!byteOk) g.fail(`字节格式化包装 ${r.byteDefs} > 基线 ${BASELINE_BYTE}（只许递减，禁止新增）`);

// ---- 正向对照（与控制样本共用 run()，不是第二套判据）----
const CONTROL_CASES = [
  // 8/11 样本的关键形态：函数声明 / 箭头 / 函数表达式 / 别名，红绿成对
  ['escapeHtml 自行实现', 'function escapeHtml(s) { return s.replace(/&/g, "&amp;"); }', { defs: 1, badForm: 1, behavior: 1 }],
  ['escapeHtml 委托', 'function escapeHtml(s) { return window.ds.esc(s); }', { defs: 1, badForm: 0, behavior: 0 }],
  ['escapeHtml 自行拼接 HTML', 'function escapeHtml(s) { return \'<b>\' + s + \'</b>\'; }', { defs: 1, badForm: 1, behavior: 0 }],
  ['esc 自行实现（旧白名单盲区）', 'function esc(s) { return s.replace(/&/g, "&amp;"); }', { defs: 1, badForm: 1, behavior: 1 }],
  ['esc 委托', 'function esc(s) { return window.ds.esc(s); }', { defs: 1, badForm: 0, behavior: 0 }],
  ['escAttr 自行实现', 'function escAttr(s) { return s; }', { defs: 1, badForm: 1, behavior: 0 }],
  ['escAttr 委托', 'function escAttr(s) { return window.ds.escAttr(s); }', { defs: 1, badForm: 0, behavior: 0 }],
  ['escAttr 函数表达式自实现', 'const escAttr = function(s) { return s; };', { defs: 1, badForm: 1, behavior: 0 }],
  ['escAttr 函数表达式委托', 'const escAttr = function(s) { return window.ds.escAttr(s); };', { defs: 1, badForm: 0, behavior: 0 }],
  ['htmlEscape 自行实现', 'function htmlEscape(s) { return s; }', { defs: 1, badForm: 1, behavior: 0 }],
  ['escapeHtml 箭头自实现', 'const escapeHtml = (s) => s.replace(/</g, "&lt;");', { defs: 1, badForm: 1, behavior: 1 }],
  ['escapeHtml 箭头委托', 'const escapeHtml = (s) => window.ds.esc(s);', { defs: 1, badForm: 0, behavior: 0 }],
  ['formatSize 自行实现', 'function formatSize(bytes) { return bytes.toFixed(1) + " KB"; }', { defs: 1, badForm: 1, behavior: 1 }],
  ['formatSize 委托', 'function formatSize(bytes) { return window.ds.fmtBytes(bytes); }', { defs: 1, badForm: 0, behavior: 0 }],
  ['fmtBytes 箭头自实现', 'const fmtBytes = (b) => (b / 1024).toFixed(1) + " KB";', { defs: 1, badForm: 1, behavior: 1 }],
  ['fmtBytes 箭头委托', 'const fmtBytes = (b) => window.ds.fmtBytes(b);', { defs: 1, badForm: 0, behavior: 0 }],
  ['formatBytes 自行实现', 'function formatBytes(n) { return n + " B"; }', { defs: 1, badForm: 1, behavior: 0 }],
  ['fmtSpeed 自行实现', 'function fmtSpeed(bps) { return (bps / 1024).toFixed(0) + " KB/s"; }', { defs: 1, badForm: 1, behavior: 1 }],
  ['fmtSpeed 委托', 'function fmtSpeed(bps) { return window.ds.fmtRate(bps); }', { defs: 1, badForm: 0, behavior: 0 }],
  ['fmtSizeKb 自行实现', 'function fmtSizeKb(kb) { return kb.toFixed(1) + " MB"; }', { defs: 1, badForm: 1, behavior: 1 }],
  ['fmtSizeKb 委托', 'function fmtSizeKb(kb) { return window.ds.fmtBytes(kb * 1024); }', { defs: 1, badForm: 0, behavior: 0 }],
  ['formatSpeed 自行实现', 'function formatSpeed(bps) { return (bps / 1024).toFixed(1) + " KB/s"; }', { defs: 1, badForm: 1, behavior: 1 }],
  ['formatBlock 委托', 'function formatBlock(size) { return window.ds.fmtBytes(size); }', { defs: 1, badForm: 0, behavior: 0 }],
  ['别名委托', 'const esc = window.ds.esc;', { defs: 1, badForm: 0, behavior: 0 }],
  ['别名错配', 'const esc = window.ds.escAttr;', { defs: 1, badForm: 1, behavior: 0 }],
  // 汇聚面：+ 拼接 / 模板插值，红绿成对
  ['+ 裸标识符', 'el.innerHTML = \'<div>\' + name + \'</div>\';', { sink: 1 }],
  ['+ 委托调用', 'el.innerHTML = \'<div>\' + escapeHtml(name) + \'</div>\';', { sink: 0 }],
  ['+ window.ds.esc', 'el.innerHTML = \'<div>\' + window.ds.esc(name) + \'</div>\';', { sink: 0 }],
  ['+ 三元裸标识符', 'el.innerHTML = \'<div>\' + (name ? name : \'\') + \'</div>\';', { sink: 1 }],
  ['+ 上游已转义', 'const label = escapeHtml(items[0].name); el.innerHTML = \'<div>\' + label + \'</div>\';', { sink: 0 }],
  ['+ 数值声明', 'const count = items.length; el.innerHTML = \'<div>\' + count + \'</div>\';', { sink: 0 }],
  ['+ 直接调用放行', 'el.innerHTML = \'<div>\' + rows.join(\'\') + \'</div>\';', { sink: 0 }],
  ['模板裸标识符', 'el.innerHTML = `<div>${name}</div>`;', { sink: 1 }],
  ['模板委托', 'el.innerHTML = `<div>${escapeHtml(name)}</div>`;', { sink: 0 }],
  ['成员字段裸值', 'el.innerHTML = \'<div>\' + item.title + \'</div>\';', { sink: 1 }],
  ['数值成员不吞三元真分支', 'el.innerHTML = \'<div>\' + (r.fileCount > 0 ? name : \'\') + \'</div>\';', { sink: 1 }],
  ['模板三元委托', 'el.innerHTML = `<div>${flag ? escapeHtml(name) : \'\'}</div>`;', { sink: 0 }],
  ['HTML 槽位放行', 'el.innerHTML = \'<div>\' + opts.bodyHtml + \'</div>\';', { sink: 0 }],
  ['数值成员放行', 'el.innerHTML = \'<div>\' + r.fileCount + \'</div>\';', { sink: 0 }],
  ['insertAdjacentHTML 裸标识符', 'el.insertAdjacentHTML(\'beforeend\', \'<div>\' + name + \'</div>\');', { sink: 1 }],
  ['insertAdjacentHTML 委托', 'el.insertAdjacentHTML(\'beforeend\', \'<div>\' + escapeHtml(name) + \'</div>\');', { sink: 0 }],
  ['跨语句构建器放行（边界已声明）', 'const rows = items.map(x => \'<b>\' + x + \'</b>\').join(\'\'); el.innerHTML = \'<div>\' + rows + \'</div>\';', { sink: 0 }],
  // 真源失活对照：ds.js 被掏空（esc/escAttr/fmtBytes/fmtRate 或 ESC_MAP 缺失）必须判红
  ['真源失活必红', 'function esc(s) { return s; }', { behavior: 1 }, 'ds.js'],
];
let controlFail = 0;
for (const [name, code, want, rel] of CONTROL_CASES) {
  const got = run([{ rel: rel || '__synth__.js', text: code }]);
  const actual = {
    defs: got.escapeDefs + got.byteDefs,
    badForm: got.badForm.length,
    behavior: got.badBehavior.length,
    sink: got.sinkViolations.reduce((n, v) => n + v.count, 0),
  };
  for (const k of Object.keys(want)) {
    if (actual[k] !== want[k]) {
      controlFail++;
      g.fail(`正向对照失败：${name} 的 ${k} 期望 ${want[k]}、实得 ${actual[k]}（判定器已失真）`);
    }
  }
}
if (controlFail === 0) {
  g.ok(`正向对照自检通过（${CONTROL_CASES.length} 组：定义名/形态/别名 + 拼接/模板/insertAdjacentHTML，红绿两向）`);
}

const transitioned = r.sinkViolations.filter((v) => declared.has(`${v.file}#${v.fn}#${v.operand}`)).length;
g.ok(`定义面 ${r.escapeDefs} 转义 / ${r.byteDefs} 字节（基线 ${BASELINE_ESC}/${BASELINE_BYTE}），形态 ${r.forms.fn}/${r.forms.arrow}/${r.forms.fnexpr}/${r.forms.alias}（声明/箭头/表达式/别名）`);
g.ok(`行为面命中 ${r.badBehavior.length} 处；汇聚面 ${r.sinkSites} 处，未委托 ${r.sinkViolations.length} 条（其中过渡登记 ${transitioned} 条）`);
if (TRANSITION.length) {
  g.ok(`过渡表（只减不增）：${TRANSITION.map((t) => `${t.file}#${t.fn}#${t.operand}×${t.count}（${t.why}）`).join('；')}`);
}

g.finish('本地转义/字节格式化门禁通过（唯一真源 ds.js，他处只许委托）');
