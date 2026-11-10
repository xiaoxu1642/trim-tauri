#!/usr/bin/env node
// check-a11y.mjs —— 可达性断言（P3-1/P3-3，2026-10-09；假绿 #7 收紧 2026-11-02）
//
// 每条「找违规型」断言都配**内置正向对照自检**（违例样本必须判红；只打印 ✓
// 的恒绿断言视同没写，AGENTS §4.1）：
//   ① 勾选框模板三属性：`class="checkbox"` 的元素必须同现
//      `role="checkbox"` / `tabindex="0"` / `aria-checked`（自绘控件三件套，
//      缺一键盘用户就摸不到/读不出；disabled 语义额外挂 aria-disabled，不在本断言范围）。
//   ② 异步状态宿主必须带 aria-live：id 以 `GlobalHint` 结尾、或为 `toastContainer`
//      的宿主，读屏靠 aria-live 才知道内容变了 —— 没有它，提示等于静默。
//   ③ `data-tip` 反 `title`（AGENTS §2）：禁 `title="` 属性与元素 `.title =` 赋值
//      （原生 title 与自绘 tooltip 会双气泡；`document.title` 是窗口标题，除外）。
//   ④ prefers-reduced-motion 归零覆盖面（v4 F1）：main.css 的 RM 归零段必须
//      点名 **body 自身**（三子窗 body fadeIn 挂在 body 上，`body > *` 漏掉它）
//      且覆盖 `::-webkit-slider-thumb`（厂商伪元素，::before/::after 式管不到）。
//   ⑩ 表单控件可访问名（T1d-M03 / F4a2-M05/M06）：input/select/textarea 必须有
//      aria-label / aria-labelledby（非空）、关联 <label for> 或隐式 <label> 文本；
//      role="button" 自绘控件必须有 aria-label / aria-labelledby / 元素内文本。
//      placeholder / data-tip / 兄弟 span 文案不是可访问名。收紧当日的存量违例
//      逐条登记在 NAME_TRANSITION（file#selector + 理由），只减不增；整文件跳过不算。
//   ⑪ 焦点三断言（T1d-M04）：默认焦点可见（逐交互面自选择器 + 弹窗 initialFocus）、
//      焦点陷阱（ds.focusTrap 的 Tab 圈闭 / focusin 外逃拉回）、关闭归还
//      （trap.release 与 prevFocus.focus）；不再用「合并 CSS 里存在任意 :focus-visible」。
//
// 扫描面地板：命中数低于粗下界即判红（防「正则过时 ⇒ 0 命中恒绿」）。
//
// 用法：node tools/check-a11y.mjs
'use strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';
import { styleLinks } from './lib/html-tags.mjs';
import { blankNonCode } from './lib/src-scan.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');

const read = (p) => readFileSync(p, 'utf8');
const htmlFiles = readdirSync(SRC).filter((f) => f.endsWith('.html')).map((f) => join(SRC, f));
// T1d-K01（v7.2 C09）：语料面从「顶层 scripts」扩到 scripts/** + vendor/**（递归）。
// src/vendor/litebox.js 是主窗运行件（app.js PAGE_SCRIPTS 在 cleanup/backups 两页注入），
// 不是只读基线；它里面有 7 处 title="（已随本批迁 data-tip），旧语料面全程看不见。
const walkJs = (base) => {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) out.push(p);
    }
  };
  walk(base);
  return out;
};
const jsFiles = [...new Set([...walkJs(join(SRC, 'scripts')), ...walkJs(join(SRC, 'vendor'))])].sort();
// 采集面地板：语料塌缩（目录改名）时「全部通过」就是空集假绿（现算 48+1，地板取显著下界）
const JS_CORPUS_FLOOR = 20;
const rel = (p) => relative(ROOT, p).replace(/\\/g, '/');

// ---------- ① 勾选框模板三属性 ----------
const CHECKBOX_ATTRS = ['role="checkbox"', 'tabindex="0"', 'aria-checked'];
function checkboxViolations(text) {
  const out = [];
  for (const m of text.matchAll(/class="checkbox/g)) {
    // 元素窗口：从 match 起到第一个 `>` 为止（这些模板的模板表达式内不含 `>`）
    const seg = text.slice(m.index, m.index + 600);
    const end = seg.indexOf('>');
    const el = end >= 0 ? seg.slice(0, end) : seg;
    const missing = CHECKBOX_ATTRS.filter((a) => !el.includes(a));
    if (missing.length) out.push(missing);
  }
  return out;
}

// ---------- ② 异步状态宿主 aria-live ----------
function ariaLiveViolations(html) {
  const out = [];
  for (const m of html.matchAll(/id="([A-Za-z]*GlobalHint|toastContainer)"/g)) {
    const open = html.lastIndexOf('<', m.index);
    const close = html.indexOf('>', m.index);
    const tag = open >= 0 && close > open ? html.slice(open, close) : '';
    if (!/aria-live\s*=/.test(tag)) out.push(m[1]);
  }
  return out;
}

// ---------- ③ data-tip 反 title ----------
function titleViolations(text, isJs) {
  const out = [];
  // 属性形态一定是 `title="…"` / `title='…'`（无空格）；带空格的 `title = ''` 是
  // 解构默认值/普通赋值，不当属性处理（避免误伤 `{ title = '' }` 参数写法）。
  for (const m of text.matchAll(/\btitle=["']/g)) out.push('title 属性');
  if (isJs) {
    for (const m of text.matchAll(/(\w[\w.]*)\.title\s*=/g)) {
      if (m[1] !== 'document') out.push(`${m[1]}.title 赋值`);
    }
  }
  return out;
}

// ---------- ④ prefers-reduced-motion 归零覆盖面 ----------
// v4 F1 红线：归零通配从 `body > *` 起算会漏掉 **body 自身**（三子窗 body fadeIn
// 就挂在 body 上）；滑块拇指 `::-webkit-slider-thumb` 是厂商伪元素，归零表的
// ::before/::after 两式覆盖不到 —— 两处各配断言，漏一处即红（点名 `body` 自身）。
function rmViolations(css) {  const out = [];
  const blocks = [...css.matchAll(/@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([\s\S]*?)\n\}/g)]
    .map((m) => m[1])
    .join('\n');
  if (!blocks) return ['没有任何 prefers-reduced-motion 归零段'];
  // ① 归零选择器表必须含**裸 body 选择器项**（`body,` 打头的表项，不是仅 `body > *`）
  if (!/(^|[\s{}])body\s*,/m.test(blocks)) out.push('归零选择器表未点名 body 自身（body fadeIn 过渡漏归零）');
  // ② 滑块拇指（厂商伪元素）过渡必须被归零
  if (!/::-webkit-slider-thumb/.test(blocks)) out.push('::-webkit-slider-thumb 过渡未归零（滑块的 scale 过渡在 RM 下仍会动）');
  return out;
}

// ---------- ⑤⑥ 交互卫生（P3-5） ----------
// ⑤ 同一元素同一事件不得重复注册（F4a-G-3 / M04 回归形态）：只判**可选链形态**
//    `X?.addEventListener('evt'` 的同 receiver+event 重复 —— 循环/多作用域里的普通
//    变量名重复（如 `btn`）是合法写法，全量判会误报洪水（现算 21 例全属此类）。
// ⑥ 子窗脚本代码不得依赖 window.app（F3-G-3）：子窗不加载 app.js，window.app 恒
//    undefined，依赖它 = 功能静默失效（注释里说明「不存在」不算）。
const RE_OPT_CHAIN_REG = /([A-Za-z_$][\w$]*)\s*\?\.\s*addEventListener\(\s*['"](\w+)['"]/g;
function dupOptChainRegistrations(text) {
  const seen = new Map();
  const out = [];
  for (const m of text.matchAll(RE_OPT_CHAIN_REG)) {
    const k = `${m[1]}|${m[2]}`;
    if (seen.has(k)) out.push(`${k}（@${seen.get(k)} 与 @${text.slice(0, m.index).split('\n').length}）`);
    else seen.set(k, text.slice(0, m.index).split('\n').length);
  }
  return out;
}
function windowAppViolations(text) {
  const out = [];
  const lines = text.split('\n');
  for (const m of text.matchAll(/window\s*\.\s*app\b/g)) {
    const lineNo = text.slice(0, m.index).split('\n').length - 1;
    const line = lines[lineNo] || '';
    // 特性探测形豁免：`if (window.app?.x)` —— 这是「两窗可用」的正确姿势
    //（探测存在性后走各自出口），不是对它的依赖。裸 `window.app?.toast(…)` 语句
    // 仍要红：可选链会把副窗的 undefined 静默吞掉，用户点了没反应。
    if (/\bif\s*\([^)]*window\s*\.\s*app/.test(line)) continue;
    out.push(`@${lineNo + 1}`);
  }
  return out;
}

// ---------- ⑩ 表单控件 / role=button 可访问名（假绿 #7，T1d-M03 / F4a2-M05/M06） ----------
// 判据只认「读屏能读出的名字」：aria-label / aria-labelledby（非空）、关联
// <label for>（label 内必须有文本）、隐式 <label> 包裹（label 内必须有文本）。
// placeholder / data-tip / title / 兄弟 span 文案都不算 —— 它们不是可访问名。
// role="button" 自绘控件允许由元素内文本命名（原生 accname 规则），纯图标/空壳必红。
// 过渡表：收紧当日的存量违例逐条登记（file#selector + 理由），只减不增；
// 新增违例不在表内即红，表内条目已修复/改名也红（要求同步删条目）。
const NAME_GENERIC_CLASSES = new Set([
  'field-input', 'syspanel-pf-input', 'syspanel-pwr-input', 'input-style', 'startup-check',
]);
// 上限固定在收紧当日条数（30）；每修复一条应同步下调，禁止借「换一条」维持总数。
const NAME_DEBT_CAP = 30;
const NAME_TRANSITION = [
  ['src/index.html#lockQueryPath', '「查询路径」是兄弟 span 文本，未与输入框关联'],
  ['src/index.html#startupDefendToggle', '开关 label 内无文字，标题「防恢复自动删除」是兄弟 div'],
  ['src/index.html#qcSearch', '只有 placeholder；placeholder 不是可访问名'],
  ['src/index.html#cleanupAgePolicy', '「全局门槛」在兄弟 span.skin-row-label'],
  ['src/index.html#presetBgSelect', '「预设壁纸」在兄弟 span.skin-row-label'],
  ['src/index.html#bgOpacity', '「雾化度」在兄弟 span.bg-opacity-label'],
  ['src/index.html#bgPosX', '「水平位置」在兄弟 span.bg-opacity-label'],
  ['src/index.html#bgPosY', '「垂直位置」在兄弟 span.bg-opacity-label'],
  ['src/index.html#wallpaperRotateToggle', '开关 label 内无文字，「自动轮换」在兄弟 span'],
  ['src/index.html#wallpaperIntervalSelect', '「轮换间隔」在兄弟 span.skin-row-label'],
  ['src/index.html#bgBlur', '「磨砂强度」在兄弟 span.bg-opacity-label'],
  ['src/index.html#mouseTrailToggle', '开关 label 内无文字，「启用鼠标拖尾」在兄弟 span'],
  ['src/index.html#liquidMotionSelect', '「效果」在兄弟 span.skin-row-label'],
  ['src/index.html#cdpToggle', '开关 label 内无文字，「远程调试 (CDP)」在兄弟 span'],
  ['src/process-manager-window.html#pmSearch', '只有 placeholder；placeholder 不是可访问名'],
  ['src/residue-window.html#rsSearch', '只有 placeholder；placeholder 不是可访问名'],
  ['src/scripts/memoryclean.js#input[data-check=${r.id}]', 'label.mem-check 内只有 CSS 方框，区域名挂在行 role=group 上'],
  ['src/scripts/models-window.js#input[data-role=enabled]', '开关 label 内只有轨道，字段名在兄弟 span.mw-field-label'],
  ['src/scripts/models-window.js#input[data-role=apiUrl]', '字段名在兄弟 span.mw-field-label，输入框无 id/aria-label'],
  ['src/scripts/models-window.js#input[data-role=apiKey]', '字段名在兄弟 span.mw-field-label，输入框无 id/aria-label'],
  ['src/scripts/models-window.js#select[data-role=model]', '字段名在兄弟 span.mw-field-label，下拉框无 id/aria-label'],
  ['src/scripts/models-window.js#input[data-role=model]', '字段名在兄弟 span.mw-field-label，输入框无 id/aria-label'],
  ['src/scripts/models-window.js#input[data-role=customName]', '字段名在兄弟 span.mw-field-label，输入框无 id/aria-label'],
  ['src/scripts/models-window.js#input[data-role=timeout]', '字段名在兄弟 span.mw-field-label，输入框无 id/aria-label'],
  ['src/scripts/optimizer.js#select.optimizer-mem-select', '动态档位下拉只有 data-tip，无 label/aria-label'],
  ['src/scripts/syspanel.js#syspanelPwrNameInput', '弹窗正文只有说明 p，输入框无 label/aria-label'],
  ['src/scripts/syspanel.js#syspanelPwrSearch', '只有 placeholder；placeholder 不是可访问名'],
  ['src/scripts/syspanel.js#input.syspanel-pf-drive', '表格列头「盘符」未与单元格输入框关联'],
  ['src/scripts/syspanel.js#input[data-field=initialMb]', '表格列头「初始 (MB)」未与单元格输入框关联'],
  ['src/scripts/syspanel.js#input[data-field=maxMb]', '表格列头「最大 (MB)」未与单元格输入框关联'],
];
const NAME_TRANSITION_MAP = new Map(NAME_TRANSITION);

function stripMarkupComments(text, isJs) {
  if (!isJs) return text.replace(/<!--[\s\S]*?-->/g, ' ');
  return blankNonCode(text, 'js', { keepStrings: true });
}
// 标签窗口必须走到引号外的 `>` 为止（属性值里可能有空格/模板表达式），
// 不能像旧实现那样直接 indexOf('>')。
function readTag(text, start) {
  let quote = null;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '>') return text.slice(start, i + 1);
  }
  return text.slice(start, start + 600);
}
// 属性解析只服务可访问名判定：支持双/单引号、布尔属性与模板表达式。
function parseTagAttrs(tag) {
  const attrs = {};
  let i = 0;
  while (i < tag.length && !/\s/.test(tag[i]) && tag[i] !== '>') i++;
  while (i < tag.length) {
    while (i < tag.length && /\s/.test(tag[i])) i++;
    if (i >= tag.length || tag[i] === '>' || tag[i] === '/') break;
    let name = '';
    while (i < tag.length && !/[\s=/>]/.test(tag[i])) name += tag[i++];
    while (i < tag.length && /\s/.test(tag[i])) i++;
    if (!name) { i++; continue; }
    if (tag[i] === '=') {
      i++;
      while (i < tag.length && /\s/.test(tag[i])) i++;
      const quote = tag[i];
      if (quote === '"' || quote === "'") {
        i++;
        let value = '';
        while (i < tag.length && tag[i] !== quote) value += tag[i++];
        i++;
        attrs[name.toLowerCase()] = value;
      } else {
        let value = '';
        while (i < tag.length && !/[\s>]/.test(tag[i])) value += tag[i++];
        attrs[name.toLowerCase()] = value;
      }
    } else {
      attrs[name.toLowerCase()] = '';
    }
  }
  return attrs;
}
// 去标签取文本：按 readTag 跳过整段标签，避免属性值里的 `>` 截断。
function markupText(markup) {
  let out = '';
  let i = 0;
  while (i < markup.length) {
    const lt = markup.indexOf('<', i);
    if (lt < 0) { out += markup.slice(i); break; }
    out += markup.slice(i, lt);
    i = lt + readTag(markup, lt).length;
  }
  return out;
}
const hasReadableText = (s) => !!s && markupText(s).replace(/\s+/g, '').length > 0;
function labelEntries(source) {
  const out = [];
  for (const m of source.matchAll(/<label\b/gi)) {
    const tag = readTag(source, m.index);
    const openEnd = m.index + tag.length;
    const close = source.indexOf('</label>', openEnd);
    if (close < 0) continue;
    const attrs = parseTagAttrs(tag);
    out.push({
      start: m.index,
      end: close,
      forAttr: (attrs.for || '').trim(),
      content: source.slice(openEnd, close),
    });
  }
  return out;
}
function enclosingLabel(entries, start) {
  let found = null;
  for (const entry of entries) {
    if (entry.start < start && start < entry.end && (!found || entry.start > found.start)) found = entry;
  }
  return found;
}
function controlSelectorKey(file, tag, attrs) {
  const tagName = (tag.match(/^<\s*([a-zA-Z][\w-]*)/) || [])[1] || 'control';
  if (attrs.id) return `${file}#${attrs.id}`;
  for (const name of ['data-role', 'data-field', 'data-check', 'data-keys', 'name']) {
    if (attrs[name]) return `${file}#${tagName}[${name}=${attrs[name]}]`;
  }
  const classes = (attrs.class || '').trim().split(/\s+/).filter(Boolean);
  const cls = classes.find((c) => !NAME_GENERIC_CLASSES.has(c)) || classes[0];
  return cls ? `${file}#${tagName}.${cls}` : `${file}#${tagName}`;
}
function elementInner(text, openEnd, tagName) {
  let depth = 1;
  const re = new RegExp('<(/?)' + tagName + '\\b[^>]*>', 'gi');
  re.lastIndex = openEnd;
  let m;
  while ((m = re.exec(text))) {
    if (m[1]) depth--; else depth++;
    if (depth === 0) return text.slice(openEnd, m.index);
  }
  return '';
}
function analyzeAccessibleNames(rawText, file, isJs) {
  const text = stripMarkupComments(rawText, isJs);
  const labels = labelEntries(text);
  const violations = [];
  let controlCount = 0;
  let namedCount = 0;
  for (const m of text.matchAll(/<(input|select|textarea)\b/gi)) {
    const tag = readTag(text, m.index);
    const attrs = parseTagAttrs(tag);
    if ((attrs.type || '').toLowerCase() === 'hidden') continue;
    if ((attrs['aria-hidden'] || '').toLowerCase() === 'true') continue;
    controlCount++;
    let named = hasReadableText(attrs['aria-label'] || '') ||
      hasReadableText(attrs['aria-labelledby'] || '');
    const type = (attrs.type || '').toLowerCase();
    if (!named && ['button', 'submit', 'reset'].includes(type)) named = hasReadableText(attrs.value || '');
    if (!named && type === 'image') named = hasReadableText(attrs.alt || '');
    if (!named && attrs.id) {
      const explicit = labels.find((l) => l.forAttr === attrs.id && hasReadableText(l.content));
      if (explicit) named = true;
    }
    if (!named) {
      const implicit = enclosingLabel(labels, m.index);
      if (implicit && hasReadableText(implicit.content)) named = true;
    }
    if (named) namedCount++;
    else {
      violations.push({
        key: controlSelectorKey(file, tag, attrs),
        why: '表单控件没有可访问名（aria-label / aria-labelledby / label for / 隐式 label 四者皆无）',
      });
    }
  }
  let roleButtonCount = 0;
  let roleButtonNamed = 0;
  // T1d-M03：可访问名断言从 role=button 扩到自绘交互控件六族。
  // 标签窗口交给 readTag，属性值里的 `>` 不会截断。
  const ROLE_CONTROLS = new Set(['button', 'checkbox', 'switch', 'radio', 'tab', 'menuitem', 'option']);
  for (const m of text.matchAll(/<[a-zA-Z][\w-]*\b/g)) {
    const tag = readTag(text, m.index);
    const attrs = parseTagAttrs(tag);
    const role = (attrs.role || '').toLowerCase();
    if (!ROLE_CONTROLS.has(role)) continue;
    roleButtonCount++;
    const tagName = (tag.match(/^<\s*([a-zA-Z][\w-]*)/) || [])[1] || 'div';
    const named = hasReadableText(attrs['aria-label'] || '') ||
      hasReadableText(attrs['aria-labelledby'] || '') ||
      hasReadableText(elementInner(text, m.index + tag.length, tagName));
    if (named) roleButtonNamed++;
    else {
      const cls = ((attrs.class || '').trim().split(/\s+/)[0] || 'anon');
      violations.push({
        key: `${file}#role=${role}:${tagName}.${cls}`,
        why: `role=${role} 自绘控件没有可访问名（aria-label / aria-labelledby / 元素内文本皆无）`,
      });
    }
  }
  return { violations, controlCount, namedCount, roleButtonCount, roleButtonNamed };
}

// ---------- ⑪ 焦点三断言（T1d-M04） ----------
// 旧判据「合并 CSS 里存在任意一条 :focus-visible」在 main.css 有 27 处时恒过。
// 新判据分三层，每一层都能被合成样本判红：
//   a 默认焦点可见：每个交互面在**该窗**合并 CSS 里必须解析出可见焦点指示
//     （自选择器或裸 :focus-visible 均可，但 outline:none 且无替代指示 ⇒ 红）；
//     弹窗必须显式给 initialFocus（确认框落主按钮，update.md 2026-10-03 裁定）。
//   b 焦点陷阱：modal/静态说明框/子窗确认框都走 ds.focusTrap；ds.js 的
//     focusTrap 必须有 Tab 圈闭、focusin 外逃拉回与初始焦点。
//   c 关闭归还：各弹窗关闭路径必须调用 trap.release()，release 内必须
//     prevFocus.focus() 把焦点还给触发元素。
const FOCUS_SURFACES = [
  { sel: '.btn', why: '按钮' },
  { sel: '.filter-tab', why: '分段标签' },
  { sel: '.checkbox', why: '自绘勾选框' },
  { sel: '.ds-menu-item', why: '菜单项' },
  { sel: '.nav-item', why: '侧边导航项' },
  { sel: '.nav-subitem', why: '侧边子导航项' },
  { sel: '.category-item', why: '分类项' },
  { sel: '.context-item', why: '右键菜单项' },
  { sel: '.toggle-switch input', why: '开关' },
  { sel: '.opt-row', why: '优化看板行' },
  { sel: '.mem-group-row', why: '进程树分组行' },
  { sel: '.mw-group-head', why: '模型分组头' },
  { sel: '.an-tm-cell', why: 'Treemap 格子' },
  { sel: '.syspanel-pwr-item', why: '电源项' },
  { sel: '.syspanel-pwr-input', why: '电源输入' },
  { sel: '.syspanel-pf-input', why: '分页文件输入' },
  { sel: '.mem-check input', why: '内存区域勾选' },
  { sel: '.mt-switch', why: '材质总开关' },
  { sel: '.sidebar-toggle-btn', why: '侧边栏折叠按钮' },
  { sel: '.usage-close', why: '弹窗关闭按钮' },
  { sel: '.tauri-caption-btn', why: '自绘标题栏按钮' },
];
function cssFocusRules(css) {
  const clean = blankNonCode(css, 'css', { keepStrings: true });
  const out = [];
  for (const m of clean.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selectorText = m[1].trim();
    if (!selectorText.includes(':focus-visible')) continue;
    out.push({
      selectors: selectorText.split(',').map((s) => s.trim()).filter(Boolean),
      decls: m[2],
    });
  }
  return out;
}
function selectorHasSurface(selector, surface) {
  if (selector === ':focus-visible') return true;
  let idx = selector.indexOf(surface);
  while (idx >= 0) {
    const before = idx === 0 ? '' : selector[idx - 1];
    const after = selector[idx + surface.length] || '';
    const beforeOk = idx === 0 || ' >+~,('.includes(before) ||
      ((surface[0] === '.' || surface[0] === '#') && /[A-Za-z0-9_*-]/.test(before));
    const afterOk = !after || ' :.#[>+~'.includes(after);
    if (beforeOk && afterOk) return true;
    idx = selector.indexOf(surface, idx + 1);
  }
  return false;
}
function declarationValue(decls, prop) {
  const m = decls.match(new RegExp('(?:^|;)\\s*' + prop + '\\s*:\\s*([^;]+)', 'i'));
  return m ? m[1].trim() : null;
}
function hasFocusAlternative(decls) {
  const boxShadow = declarationValue(decls, 'box-shadow');
  if (boxShadow && !/^none(?:\s|$)/i.test(boxShadow)) return true;
  for (const prop of ['background', 'background-color']) {
    const value = declarationValue(decls, prop);
    if (value && !/^(none|transparent)(?:\s|$)/i.test(value)) return true;
  }
  for (const prop of ['border', 'border-color', 'border-top-color', 'border-right-color', 'border-bottom-color', 'border-left-color']) {
    const value = declarationValue(decls, prop);
    if (value && !/^(none|transparent|0)(?:\s|$)/i.test(value)) return true;
  }
  const color = declarationValue(decls, 'color');
  if (color && !/^(transparent|inherit)(?:\s|$)/i.test(color)) return true;
  const decoration = declarationValue(decls, 'text-decoration');
  if (decoration && !/^none(?:\s|$)/i.test(decoration)) return true;
  return false;
}
function focusVisibleFor(css, surface) {
  let outlineVisible = false;
  let alternativeVisible = false;
  let matched = 0;
  for (const rule of cssFocusRules(css)) {
    if (!rule.selectors.some((selector) => selectorHasSurface(selector, surface))) continue;
    matched++;
    const outline = declarationValue(rule.decls, 'outline');
    if (outline) outlineVisible = !/^(none|0(?:px)?)(?:\s|$)/i.test(outline);
    if (hasFocusAlternative(rule.decls)) alternativeVisible = true;
  }
  return { visible: outlineVisible || alternativeVisible, matched };
}
function sliceBetween(text, startNeedle, endNeedle) {
  const start = text.indexOf(startNeedle);
  if (start < 0) return null;
  const end = text.indexOf(endNeedle, start + startNeedle.length);
  return text.slice(start, end > start ? end : Math.min(text.length, start + 6000));
}
function focusTrapMissing(code) {
  const clean = blankNonCode(code, 'js', { keepStrings: true });
  const out = [];
  if (!clean.includes("e.key !== 'Tab'")) out.push('没有 Tab 键判定');
  if (!clean.includes('preventDefault')) out.push('没有 Tab 默认行为拦截');
  if (!clean.includes("addEventListener('focusin'")) out.push('没有 focusin 监听');
  if (!clean.includes('container.contains(document.activeElement)')) out.push('没有容器归属判定');
  if (!clean.includes('target.focus()')) out.push('没有初始焦点');
  if (!clean.includes('prevFocus.focus()')) out.push('没有关闭归还');
  return out;
}
function modalFocusMissing(code) {
  const clean = blankNonCode(code, 'js', { keepStrings: true });
  const out = [];
  if (!clean.includes('ds.focusTrap(')) out.push('未接 ds.focusTrap');
  if (!clean.includes('initialFocus: \'[data-confirm="ok"]\'')) out.push('确认框默认焦点未落主按钮');
  if (!clean.includes('trap.release()') && !clean.includes('trap?.release()')) out.push('关闭未调用 trap.release');
  return out;
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// ---------- ⑦ 折叠头 / 行点击头的键盘接线（A3-M03，2026-10-25 D 轮） ----------
// 形状：div/span 当折叠开关，或「点击整行看详情」是唯一入口，却只挂 click ⇒ 键盘既
// 聚焦不了也按不动。`ds.accordion.enhance` 只补 ARIA，**不算**键盘通路（A3 实测两个
// 调用点都以为自己有护栏）。修法：绑定处补 tabindex + role + keydown(Enter/Space→click)。
// 判据 = 「点名站点还在 + 同文件必须有键盘绑定」：站点被搬走 → 本条点名红；
// 键盘绑定被删 → 本条红。为什么不塞进 ds.js 做通用件：ds.js 在首屏 12 脚本内，
// 而首屏预算 2026-10-22 已裁定不再上调（现算余量 48 B），这条能力只有按需页用。
const COLLAPSE_SITES = [
  { file: 'src/scripts/cleanup.js', needle: '[data-group-toggle]', why: '磁盘清理一级分类折叠' },
  { file: 'src/scripts/cleanup.js', needle: '[data-sub-toggle]', why: '磁盘清理二级分类折叠' },
  { file: 'src/scripts/pathbinding.js', needle: 'systemInfoToggle', why: '设置页系统信息折叠头' },
  { file: 'src/scripts/pathbinding-background.js', needle: 'bgListToggle', why: '已导入图片列表折叠头' },
  { file: 'src/scripts/memoryclean.js', needle: '.mem-region-row', why: '内存清理区域行（点击查看简介是唯一入口）' },
  { file: 'src/scripts/processes.js', needle: 'mem-group-row', why: '进程树分组行（aria-expanded 的展开/收起）' },
  { file: 'src/scripts/optimizer.js', needle: 'opt-row', why: '优化看板行（点击查看详情/还原是唯一入口）' },
  { file: 'src/scripts/models-window.js', needle: 'mw-group-head', why: '大模型管理分组头折叠' },
  { file: 'src/scripts/finder.js', needle: 'an-tm-cell', why: 'Treemap 格子下钻（role=button）' },
  { file: 'src/scripts/startup.js', needle: 'tabindex="0" role="button"', why: '启动项行卡键盘打开详情' },
  { file: 'src/scripts/maintenance.js', needle: 'maint-card', why: '系统维护行卡键盘打开详情' },
  { file: 'src/scripts/contextmenu.js', needle: 'ctx-kanban-row', why: '右键菜单行键盘打开详情' },
  { file: 'src/scripts/contextmenu.js', needle: 'ctx-reg-jump', why: '注册表路径键盘打开 regedit' },
];
function collapseKeyWiring(text) {
  return /addEventListener\(\s*['"]keydown['"]/.test(text) && /['"]Enter['"]/.test(text);
}

// ---------- ⑧ 会变的状态面 live region 覆盖（A3-M01，2026-10-26） ----------
// A3 报告的总数与它自己列出的坐标对不上：本门禁以**坐标清单**为准（进度块 / 计数与摘要 /
// 实时数值 / 状态文字四类），不按报告总数凑数，差异记在台账。进度块的宿主挂容器 ——
// label/value 是子节点，再挂一层会双重播报。
// 主窗的坐标由 src/scripts/a11y-live.js 在首帧后挂（走 IDLE_SCRIPTS，字节不进首屏预算）；
// 子窗 pmCount 与 maintBatchProgressText 直接写 HTML —— 后者本来就有宿主（文字节点），
// 块本体不再挂。实时数值挂 off（2026-10-26 小旭拍板：每秒播报对读屏不可用）。
const LIVE_MOUNT_FILE = join(SRC, 'scripts', 'a11y-live.js');
const APP_JS_FILE = join(SRC, 'scripts', 'app.js');
const LIVE_BASELINE = [
  { id: 'dupProgressSection', mode: 'polite', where: 'idle' },
  { id: 'emptyProgressSection', mode: 'polite', where: 'idle' },
  { id: 'anProgressSection', mode: 'polite', where: 'idle' },
  { id: 'totalSize', mode: 'polite', where: 'idle' },
  { id: 'selectedCount', mode: 'polite', where: 'idle' },
  { id: 'dupGroupCount', mode: 'polite', where: 'idle' },
  { id: 'dupSize', mode: 'polite', where: 'idle' },
  { id: 'emptyCount', mode: 'polite', where: 'idle' },
  { id: 'emptyDirCount', mode: 'polite', where: 'idle' },
  { id: 'anTotalSize', mode: 'polite', where: 'idle' },
  { id: 'anCounts', mode: 'polite', where: 'idle' },
  { id: 'anElapsed', mode: 'polite', where: 'idle' },
  { id: 'memRegionCount', mode: 'polite', where: 'idle' },
  { id: 'optimizerSummary', mode: 'polite', where: 'idle' },
  { id: 'contextSummary', mode: 'polite', where: 'idle' },
  { id: 'ovHealthCard', mode: 'polite', where: 'idle' },
  { id: 'ovHealthAdvice', mode: 'polite', where: 'idle' },
  { id: 'lockQueryResult', mode: 'polite', where: 'idle' },
  { id: 'startupDefendState', mode: 'polite', where: 'idle' },
  { id: 'qcCount', mode: 'polite', where: 'idle' },
  { id: 'cleanupAgeHint', mode: 'polite', where: 'idle' },
  { id: 'updaterCheckHint', mode: 'polite', where: 'idle' },
  { id: 'infoCdpState', mode: 'polite', where: 'idle' },
  { id: 'memUseValue', mode: 'off', where: 'idle' },
  { id: 'memFreeValue', mode: 'off', where: 'idle' },
  { id: 'memPagefileValue', mode: 'off', where: 'idle' },
  { id: 'memCacheValue', mode: 'off', where: 'idle' },
  { id: 'realtimeDown', mode: 'off', where: 'idle' },
  { id: 'realtimeUp', mode: 'off', where: 'idle' },
  { id: 'realtimeLossDetail', mode: 'off', where: 'idle' },
  { id: 'contextDisabledSummary', mode: 'polite', where: 'idle' },
  { id: 'maintBatchProgressText', mode: 'polite', where: 'html' },
  { id: 'pmCount', mode: 'polite', where: 'html' },
];
function parseLiveMountTable(text) {
  const grab = (name) => {
    const m = text.match(new RegExp(name + '\\s*=\\s*\\[([\\s\\S]*?)\\]'));
    return m ? [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]) : null;
  };
  return { polite: grab('POLITE_HOSTS'), off: grab('LIVE_OFF_HOSTS') };
}
function tagOfId(htmlText, id) {
  const m = htmlText.match(new RegExp('id="' + id + '"'));
  if (!m) return null;
  const open = htmlText.lastIndexOf('<', m.index);
  const close = htmlText.indexOf('>', m.index);
  return open >= 0 && close > open ? htmlText.slice(open, close + 1) : null;
}
function liveCoverageProblems(table, baseline, findTag) {
  const out = [];
  if (!table || !table.polite || !table.off) return ['挂载表解析不到 POLITE_HOSTS / LIVE_OFF_HOSTS（判定失明）'];
  const baseIds = new Set(baseline.map((b) => b.id));
  for (const { id, mode, where } of baseline) {
    if (where === 'idle') {
      const list = mode === 'polite' ? table.polite : table.off;
      if (!list.includes(id)) out.push(`${id} 未按 ${mode} 出现在 a11y-live.js（漏挂或挂错档）`);
    } else {
      const tag = findTag(id);
      if (!tag) out.push(`${id} 在任何 HTML 里都找不到`);
      else if (!new RegExp("aria-live\\s*=\\s*[\"']" + mode + "[\"']").test(tag)) {
        out.push(`${id} 的 HTML 宿主缺 aria-live="${mode}"`);
      }
    }
  }
  for (const [mode, ids] of [['polite', table.polite], ['off', table.off]]) {
    for (const id of ids) {
      if (!baseIds.has(id)) out.push(`${id} 在挂载表（${mode}）里但不在门禁基线 —— 新增面必须同步基线`);
    }
  }
  const dup = table.polite.filter((id) => table.off.includes(id));
  if (dup.length) out.push(`同一 id 挂在两档：${dup.join('、')}`);
  return out;
}

console.log('=== 可达性门禁（勾选框三属性 / aria-live 宿主 / data-tip 反 title / 可访问名 / 焦点管理）===\n');

// ---- 正向对照自检：判定器必须能对违例样本判红、对合规样本放行 ----
{
  const badCheckbox = '<span class="checkbox checked" data-x="1"></span>';
  const goodCheckbox =
    '<span class="checkbox" data-x="1" role="checkbox" tabindex="0" aria-checked="false"></span>';
  check(checkboxViolations(badCheckbox).length === 1, '对照①a：缺三属性的勾选框样本必须判红');
  check(checkboxViolations(goodCheckbox).length === 0, '对照①b：三属性齐全的样本必须放行');

  const badLive = '<span class="mw-foot-hint" id="xxGlobalHint" style="margin:0"></span>';
  const goodLive = '<span id="xxGlobalHint" role="status" aria-live="polite"></span>';
  check(ariaLiveViolations(badLive).length === 1, '对照②a：无 aria-live 的提示宿主必须判红');
  check(ariaLiveViolations(goodLive).length === 0, '对照②b：带 aria-live 的宿主必须放行');

  const badTitle = '<div title="旧提示"></div>';
  const badTitleJs = "el.title = '旧提示';";
  const goodTitleJs = "document.title = '窗口标题'; el.setAttribute('data-tip', '新提示');";
  check(titleViolations(badTitle, false).length === 1, '对照③a：title 属性样本必须判红');
  check(titleViolations(badTitleJs, true).length === 1, '对照③b：元素 .title 赋值样本必须判红');
  check(titleViolations(goodTitleJs, true).length === 0, '对照③c：document.title 与 data-tip 样本必须放行');

  const badRmNoBody = '@media (prefers-reduced-motion: reduce) {\n  body > *:not(#splash) { animation-duration: 0.01ms !important; }\n}\n';
  const badRmNoThumb = '@media (prefers-reduced-motion: reduce) {\n  body, body > * { transition-duration: 0.01ms !important; }\n}\n';
  const goodRm = '@media (prefers-reduced-motion: reduce) {\n  body,\n  body > *:not(#splash) { transition-duration: 0.01ms !important; }\n  input[type="range"]::-webkit-slider-thumb { transition-duration: 0.01ms !important; }\n}\n';
  check(rmViolations(badRmNoBody).some((v) => v.includes('body 自身')), '对照④a：归零表漏 body 自身的样本必须判红');
  check(rmViolations(badRmNoThumb).some((v) => v.includes('slider-thumb')), '对照④b：拇指未归零的样本必须判红');
  check(rmViolations(goodRm).length === 0, '对照④c：body 自身 + 拇指都归零的样本必须放行');

  const badDup = "a?.addEventListener('click', f1);\na?.addEventListener('click', f2);";
  const goodDup = "a?.addEventListener('click', f1);\nb.addEventListener('click', f2);\nrows.forEach(el => el.addEventListener('click', f3));";
  check(dupOptChainRegistrations(badDup).length === 1, '对照⑤a：同元素同事件的可选链重复注册必须判红');
  check(dupOptChainRegistrations(goodDup).length === 0, '对照⑤b：不同元素/循环内注册必须放行');
  check(windowAppViolations('const x = window.app?.toast?.(1);').length === 1, '对照⑥a：子窗代码依赖 window.app 必须判红');
  check(!collapseKeyWiring("el.addEventListener('click', f);"), '对照⑦a：只有 click 绑定的折叠头样本必须判红');
  check(collapseKeyWiring("el.addEventListener('keydown', e => { if (e.key === 'Enter') el.click(); });"), '对照⑦b：补了 Enter 键盘通路的样本必须放行');

  const base = [
    { id: 'a', mode: 'polite', where: 'idle' },
    { id: 'c', mode: 'off', where: 'idle' },
    { id: 'p', mode: 'polite', where: 'html' },
  ];
  const goodTable = { polite: ['a'], off: ['c'] };
  const goodTag = (id) => (id === 'p' ? '<span id="p" role="status" aria-live="polite">' : null);
  check(liveCoverageProblems(goodTable, base, goodTag).length === 0, '对照⑧a：覆盖齐全的样本必须放行');
  check(liveCoverageProblems({ polite: [], off: ['c'] }, base, goodTag).some((v) => v.includes('a ')), '对照⑧b：漏挂必须判红');
  check(liveCoverageProblems({ polite: [], off: ['a', 'c'] }, base, goodTag).some((v) => v.includes('a ')), '对照⑧c：挂错档必须判红');
  check(liveCoverageProblems(goodTable, base, () => '<span id="p">').some((v) => v.includes('aria-live')), '对照⑧d：HTML 宿主缺属性必须判红');
  check(liveCoverageProblems({ polite: ['a', 'x'], off: ['c'] }, base, goodTag).some((v) => v.includes('x ')), '对照⑧e：表里多出未登记 id 必须判红');
  check(liveCoverageProblems({ polite: ['a'], off: ['c', 'a'] }, base, goodTag).some((v) => v.includes('两档')), '对照⑧f：同 id 挂两档必须判红');
  check(liveCoverageProblems(null, base, goodTag).length > 0, '对照⑧g：挂载表解析不到必须判红');

  // ⑩ 可访问名：四组必测（无名字 / label for / aria-label / 仅注释）+ 隐式 label、
  // 空 label、aria-labelledby、role=button 文本命名。
  const nameNone = '<input type="text" id="a" />';
  const nameLabelFor = '<label for="a">名称</label><input type="text" id="a" />';
  const nameAria = '<input type="text" aria-label="名称" />';
  const nameCommented = '<!-- <input type="text" aria-label="注释里的名字" /> --><input type="text" id="b" />';
  const nameImplicit = '<label>名称<input type="text" /></label>';
  const nameEmptyLabel = '<label for="a"></label><input type="text" id="a" />';
  const nameLabelledby = '<span id="t">名称</span><input type="text" aria-labelledby="t" />';
  const roleEmpty = '<div role="button" tabindex="0"><svg></svg></div>';
  const roleText = '<div role="button" tabindex="0">关闭</div>';
  check(analyzeAccessibleNames(nameNone, 'sample.html', false).violations.length === 1, '对照⑩a：无名字的表单控件必须判红');
  check(analyzeAccessibleNames(nameLabelFor, 'sample.html', false).violations.length === 0, '对照⑩b：label for 关联必须放行');
  check(analyzeAccessibleNames(nameAria, 'sample.html', false).violations.length === 0, '对照⑩c：aria-label 必须放行');
  check(analyzeAccessibleNames(nameCommented, 'sample.html', false).violations.length === 1, '对照⑩d：只在注释里出现的名字不算');
  check(analyzeAccessibleNames(nameImplicit, 'sample.html', false).violations.length === 0, '对照⑩e：隐式 label 文本必须放行');
  check(analyzeAccessibleNames(nameEmptyLabel, 'sample.html', false).violations.length === 1, '对照⑩f：空 label 不算名字');
  check(analyzeAccessibleNames(nameLabelledby, 'sample.html', false).violations.length === 0, '对照⑩g：aria-labelledby 必须放行');
  check(analyzeAccessibleNames(roleEmpty, 'sample.html', false).violations.length === 1, '对照⑩h：无名字的 role=button 必须判红');
  check(analyzeAccessibleNames(roleText, 'sample.html', false).violations.length === 0, '对照⑩i：元素内文本命名 role=button 必须放行');

  // ⑪ 焦点：逐面可见 / 焦点陷阱 / 关闭归还，各配判红与放行样本。
  check(!focusVisibleFor('', '.btn').visible, '对照⑪a1：没有任何焦点规则的样本必须判红');
  check(
    focusVisibleFor('.btn:focus-visible { outline: 2px solid red; }', '.btn').visible &&
      !focusVisibleFor('.btn:focus-visible { outline: 2px solid red; }', '.filter-tab').visible,
    '对照⑪a2：只给 .btn 规则时 .filter-tab 必须判红（逐面判定）',
  );
  check(!focusVisibleFor('.btn:focus-visible { outline: none; }', '.btn').visible, '对照⑪a3：outline:none 且无替代指示必须判红');
  check(focusVisibleFor('.btn:focus-visible { outline: none; background: var(--accent-soft); }', '.btn').visible, '对照⑪a4：outline:none + 背景替代必须放行');
  check(focusVisibleFor(':focus-visible { outline: 2px solid red; }', '.filter-tab').visible, '对照⑪a5：裸 :focus-visible 全局规则必须放行');

  const goodTrap = [
    "const t = window.ds.focusTrap(el, { initialFocus: '#ok' });",
    "function onKey(e) { if (e.key !== 'Tab') return; e.preventDefault(); }",
    "document.addEventListener('focusin', onFocusIn);",
    'if (!container.contains(document.activeElement)) target.focus();',
    'target.focus();',
    'prevFocus.focus();',
  ].join('\n');
  check(focusTrapMissing('').length >= 4, '对照⑪b1：缺 Tab 圈闭/归属判定/归还的陷阱样本必须判红');
  check(focusTrapMissing(goodTrap).length === 0, '对照⑪b2：三件齐全的焦点陷阱样本必须放行');

  const goodModal = [
    'const trap = window.ds.focusTrap(modalEl, { initialFocus: opts.initialFocus });',
    `const confirmOpts = { initialFocus: '[data-confirm="ok"]' };`,
    'function close() { trap.release(); }',
  ].join('\n');
  check(modalFocusMissing('').length === 3, '对照⑪c1：默认焦点/陷阱/归还三缺的弹窗样本必须判红');
  check(modalFocusMissing(goodModal).length === 0, '对照⑪c2：三件齐全的弹窗样本必须放行');
}

// ---- 真仓扫描 ----
const g = gate(import.meta.url);
const sources = [...htmlFiles.map((p) => [p, read(p), false]), ...jsFiles.map((p) => [p, read(p), true])];

let checkboxSites = 0;
let liveHosts = 0;
let tipSites = 0;
for (const [p, text, isJs] of sources) {
  for (const miss of checkboxViolations(text)) {
    g.fail(`${rel(p)}：勾选框模板缺 ${miss.join('、')}（自绘控件三件套必须同现）`);
  }
  checkboxSites += [...text.matchAll(/class="checkbox/g)].length;

  if (!isJs) {
    for (const id of ariaLiveViolations(text)) g.fail(`${rel(p)}：#${id} 宿主必须带 aria-live（异步状态读屏靠它）`);
  }
  liveHosts += [...text.matchAll(/id="([A-Za-z]*GlobalHint|toastContainer)"/g)].length;

  for (const what of titleViolations(text, isJs)) g.fail(`${rel(p)}：${what}（提示一律走 data-tip，AGENTS §2）`);
  tipSites += [...text.matchAll(/data-tip/g)].length;
}

// ---- ⑦ 真仓扫描：折叠头键盘接线 ----
{
  const byRel = new Map(sources.map(([p, text]) => [rel(p).replace(/\\/g, '/'), text]));
  let wired = 0;
  for (const s of COLLAPSE_SITES) {
    const text = byRel.get(s.file);
    if (text === undefined) {
      g.fail(`⑦ 站点文件 ${s.file} 不在扫描面里（改名/移出 ⇒ 清单与语料必须同步，本条不能静默跳过）`);
      continue;
    }
    if (!text.includes(s.needle)) {
      g.fail(`⑦ ${s.file} 找不到锚点 ${s.needle}（${s.why}）⇒ 站点被搬走或改名，键盘接线判据已失明`);
      continue;
    }
    if (!collapseKeyWiring(text)) {
      g.fail(`⑦ ${s.file} 的折叠头 ${s.needle} 缺键盘等价路径（${s.why}）：只挂 click ⇒ 键盘用户折叠不了、也打不开详情`);
      continue;
    }
    wired++;
  }
  if (wired === COLLAPSE_SITES.length) g.ok(`⑦ 折叠头/行点击头键盘接线 ${wired}/${COLLAPSE_SITES.length} 站点全部在位`);
}

// ---- ⑧ 真仓扫描：live region 覆盖（A3-M01） ----
if (g.skipUnlessPresent(LIVE_MOUNT_FILE, 'src/scripts/a11y-live.js（A3-M01 挂载表）')) {
  const appText = existsSync(APP_JS_FILE) ? read(APP_JS_FILE) : '';
  const idleBlock = (appText.match(/IDLE_SCRIPTS\s*=\s*\[([\s\S]*?)\]/) || [])[1] || '';
  if (!idleBlock.includes("'scripts/a11y-live.js'")) {
    g.fail('⑧ a11y-live.js 没登记进 app.js 的 IDLE_SCRIPTS ⇒ 挂载表是死代码（页面永远不会挂上）');
  } else if (appText) {
    g.ok('⑧ a11y-live.js 已登记进 IDLE_SCRIPTS（首帧后挂载，不占首屏预算）');
  }
  const table = parseLiveMountTable(read(LIVE_MOUNT_FILE));
  const htmlTexts = htmlFiles.map((p) => read(p));
  const findTag = (id) => {
    for (const t of htmlTexts) {
      const tag = tagOfId(t, id);
      if (tag) return tag;
    }
    return null;
  };
  for (const v of liveCoverageProblems(table, LIVE_BASELINE, findTag)) g.fail(`⑧ ${v}`);
  if (table && table.polite && table.off) {
    if (table.polite.length < 20) g.fail(`⑧ polite 表只解析到 ${table.polite.length} 条（< 20）⇒ 语料塌缩`);
    if (table.off.length < 6) g.fail(`⑧ off 表只解析到 ${table.off.length} 条（< 6）⇒ 语料塌缩`);
    const htmlHosts = LIVE_BASELINE.filter((b) => b.where === 'html').length;
    g.ok(`⑧ live region 覆盖 ${LIVE_BASELINE.length} 个宿主（idle polite ${table.polite.length} / off ${table.off.length} + HTML 宿主 ${htmlHosts}）`);
  }
}

// ---- ⑨ reduced-motion 必须实时求值（T1d-L11） ----
// ds.js 的正确姿势是**缓存 MQL 对象**、每次读 `.matches`（src/scripts/ds.js:31-44）；一旦写成
// `const RM = matchMedia(...).matches`，值在加载时固化，用户中途切换系统偏好不再生效。
// 静态归零段（④）只能证明「RM 下有归零规则」，证明不了「判定还在听系统」。
function frozenRmConstants(code) {
  // 媒体查询串里自带括号（`(prefers-reduced-motion: reduce)`），所以参数段用惰性跨括号，
  // 由 `\)\s*\.matches` 反向锚定到 matchMedia 的外层右括号。
  return [...code.matchAll(/(?:const|let|var)\s+([\w$]+)\s*=\s*(?:window\.)?matchMedia\([\s\S]*?\)\s*\.matches/g)]
    .map((m) => m[1]);
}
{
  const scriptFiles = jsFiles.filter((p) => rel(p).startsWith('src/scripts/'));
  const stripComments = (t) => blankNonCode(t, 'js', { keepStrings: true });
  for (const p of scriptFiles) {
    const clean = stripComments(read(p));
    for (const name of frozenRmConstants(clean)) {
      g.fail(`${rel(p)}：${name} = matchMedia(...).matches 在加载时固化了 RM 判定 —— 系统偏好切换后不再生效，改为缓存 MQL 对象并每次读 .matches`);
    }
  }
  // 正向对照：固化样本必须命中；ds.js 的对象缓存姿势必须放行（判据不是恒红也非失明）。
  const frozenSample = frozenRmConstants("const RM = window.matchMedia('(prefers-reduced-motion: reduce)').matches;");
  const mqlSample = frozenRmConstants("const MQ = window.matchMedia('(prefers-reduced-motion: reduce)'); if (MQ.matches) {}");
  if (frozenSample.length !== 1 || mqlSample.length !== 0) {
    g.fail('⑨ 判据正向对照失败：固化常量样本未命中或 MQL 对象缓存样本被误伤');
  } else {
    g.ok(`⑨ reduced-motion 实时求值：${scriptFiles.length} 个脚本无加载时固化的 .matches 常量（对照：固化样本命中 / MQL 缓存放行）`);
  }
}

// ---- ⑩ 真仓扫描：表单控件 / role=button 可访问名（假绿 #7） ----
{
  const before = g.failed;
  let controls = 0;
  let named = 0;
  let roleButtons = 0;
  let roleNamed = 0;
  const violations = [];
  for (const [p, text, isJs] of sources) {
    const report = analyzeAccessibleNames(text, rel(p), isJs);
    controls += report.controlCount;
    named += report.namedCount;
    roleButtons += report.roleButtonCount;
    roleNamed += report.roleButtonNamed;
    violations.push(...report.violations);
  }
  // 语料/判据地板：正则失明时 violations=0 会假绿，必须用命中数兜底。
  if (controls < 40) g.fail(`⑩ 表单控件只扫到 ${controls} 个（< 40）⇒ 扫描面疑似失明`);
  if (named < 20) g.fail(`⑩ 可访问名只认出 ${named} 个（< 20）⇒ 判据疑似失明`);
  if (roleButtons < 8) g.fail(`⑩ role=button 只扫到 ${roleButtons} 个（< 8）⇒ 扫描面疑似失明`);
  const seen = new Set();
  let duplicate = false;
  for (const v of violations) {
    if (seen.has(v.key)) {
      duplicate = true;
      g.fail(`⑩ 过渡表键不唯一：${v.key} 命中多条，无法逐条核销`);
    }
    seen.add(v.key);
    if (!NAME_TRANSITION_MAP.has(v.key)) {
      g.fail(`⑩ ${v.key}：${v.why}（新增违例必须修产品代码；过渡表只减不增）`);
    }
  }
  for (const [key] of NAME_TRANSITION) {
    if (!seen.has(key)) {
      g.fail(`⑩ 过渡表条目 ${key} 已不再命中（违例已修复或选择器改名）⇒ 从 NAME_TRANSITION 删除该条（只减不增）`);
    }
  }
  if (NAME_TRANSITION.length > NAME_DEBT_CAP) {
    g.fail(`⑩ 过渡表 ${NAME_TRANSITION.length} 条 > 上限 ${NAME_DEBT_CAP}（只减不增）`);
  }
  if (g.failed === before && !duplicate) {
    g.ok(`⑩ 可访问名：表单控件 ${controls} 个（已命名 ${named}）+ role=button ${roleButtons} 个（已命名 ${roleNamed}）；过渡表 ${NAME_TRANSITION.length}/${NAME_DEBT_CAP} 条，当前命中 ${violations.length} 条`);
  }
}

// ---- ⑪ 真仓扫描：焦点陷阱 / 默认焦点 / 关闭归还（T1d-M04） ----
{
  const before = g.failed;
  const readScript = (name) => {
    const p = join(SRC, 'scripts', name);
    return existsSync(p) ? read(p) : null;
  };
  const modalText = readScript('modal.js');
  const dsText = readScript('ds.js');
  const appText = readScript('app.js');
  const pmText = readScript('process-manager-window.js');
  for (const [name, text] of [
    ['modal.js', modalText], ['ds.js', dsText], ['app.js', appText], ['process-manager-window.js', pmText],
  ]) {
    if (!text) g.fail(`⑪ 缺少 src/scripts/${name} ⇒ 焦点判据失明（不接受跳过）`);
  }

  if (modalText) {
    const create = sliceBetween(modalText, 'function create(opts', '// 便捷确认框');
    const confirm = sliceBetween(modalText, 'function confirm({', '// 关闭当前全部弹窗');
    const close = sliceBetween(modalText, 'close(reason) {', 'liveCtrls.add(ctrl)');
    if (!create) g.fail('⑪ modal.js create() 切片锚点失效，焦点陷阱/默认焦点无法判定');
    if (!confirm) g.fail('⑪ modal.js confirm() 切片锚点失效，默认焦点无法判定');
    if (!close) g.fail('⑪ modal.js close() 切片锚点失效，关闭归还无法判定');
    if (create && !create.includes('initialFocus: opts.initialFocus')) {
      g.fail('⑪ modal.js create() 未把 opts.initialFocus 传给 ds.focusTrap（默认焦点不可配）');
    }
    if (create && confirm && close) {
      for (const m of modalFocusMissing([create, confirm, close].join('\n'))) g.fail(`⑪ modal.js：${m}`);
    }
  }

  if (dsText) {
    const trap = sliceBetween(dsText, 'function focusTrap(', 'ds.focusTrap = focusTrap');
    const release = trap ? sliceBetween(trap, 'function release() {', 'if (active) {') : null;
    if (!trap) g.fail('⑪ ds.js focusTrap 切片锚点失效，Tab 圈闭/外逃拉回无法判定');
    if (!release) g.fail('⑪ ds.js focusTrap.release 切片锚点失效，关闭归还无法判定');
    if (trap && release) {
      for (const m of focusTrapMissing([trap, release].join('\n'))) g.fail(`⑪ ds.focusTrap：${m}`);
    }
  }

  if (appText) {
    const usage = sliceBetween(appText, 'async function showUsageGuide()', 'function closeUsageGuide()');
    const usageClose = sliceBetween(appText, 'function closeUsageGuide()', 'function escapeHtml');
    if (!usage || !usage.includes('ds.focusTrap(')) g.fail('⑪ app.js 使用说明弹窗未接 ds.focusTrap（焦点陷阱缺失）');
    if (!usage || !usage.includes("initialFocus: '#btnUsageClose'")) g.fail('⑪ app.js 使用说明弹窗未显式落初始焦点');
    if (!usageClose || !usageClose.includes('usageTrap.release()')) g.fail('⑪ app.js 使用说明弹窗关闭未归还焦点');
  }

  if (pmText) {
    const pmConfirm = sliceBetween(pmText, 'function confirmDialog(', 'let currentProcesses');
    const pmCleanup = sliceBetween(pmText, 'function cleanup(result) {', 'function escHandler');
    if (!pmConfirm || !pmConfirm.includes('ds.focusTrap(')) g.fail('⑪ process-manager-window.js 确认框未接 ds.focusTrap（焦点陷阱缺失）');
    if (!pmConfirm || !pmConfirm.includes("initialFocus: '#pmConfirmOk'")) g.fail('⑪ process-manager-window.js 确认框默认焦点未落主按钮');
    if (!pmCleanup || !pmCleanup.includes('trap?.release()')) g.fail('⑪ process-manager-window.js 确认框关闭未归还焦点');
  }

  if (g.failed === before) {
    g.ok('⑪ 焦点管理：modal.js / 使用说明弹窗 / 进程确认框三处均把默认焦点、焦点陷阱、关闭归还接在 ds.focusTrap 上');
  }
}

// ---- ⑫ 灯箱可访问名与缩略图选中态（P2/C-W1 F4a1-L19） ----
{
  const lbText = read(join(SRC, 'vendor', 'litebox.js'));
  const cleanText = read(join(SRC, 'scripts', 'cleanup.js'));
  const judge = (lb, clean) => lb.includes("this.dialog.setAttribute('aria-label', '图片预览')")
    && lb.includes("this.dialog.setAttribute('aria-label', caption ? '图片预览：' + caption : '图片预览')")
    && clean.includes('aria-selected="true"')
    && clean.includes("btn.setAttribute('aria-selected', 'true')")
    && clean.includes("btn.setAttribute('aria-selected', 'false')");
  const POS_LB = "this.dialog.setAttribute('aria-label', '图片预览');\nthis.dialog.setAttribute('aria-label', caption ? '图片预览：' + caption : '图片预览');";
  const POS_CLEAN = "const cur = selected ? ' aria-current=\"true\" aria-selected=\"true\"' : ' aria-selected=\"false\"';\nbtn.setAttribute('aria-selected', 'true');\nbtn.setAttribute('aria-selected', 'false');";
  const NEG_LB = "this.dialog.classList.add('litebox');";
  const NEG_CLEAN = "btn.setAttribute('aria-current', 'true');";
  if (!judge(POS_LB, POS_CLEAN) || judge(NEG_LB, NEG_CLEAN)) {
    g.fail('⑫ 正向对照失败：灯箱可访问名/缩略图选中态判定器失真');
  }
  if (!judge(lbText, cleanText)) {
    g.fail('⑫ litebox dialog 缺 aria-label，或缩略图 option 缺 aria-selected 同步 ⇒ 读屏读不到名称与选中态');
  } else {
    g.ok('⑫ litebox dialog 有可读名称，缩略图 option 的 aria-selected 与当前图同步');
  }
}

// ---- 扫描面地板（低于粗下界 ⇒ 疑似正则/目录失明，判红） ----
if (checkboxSites < 4) g.fail(`勾选框模板命中 ${checkboxSites} 处（< 4）⇒ 扫描面疑似失明`);
if (liveHosts < 4) g.fail(`异步提示宿主命中 ${liveHosts} 处（< 4）⇒ 扫描面疑似失明`);
if (tipSites < 10) g.fail(`data-tip 命中 ${tipSites} 处（< 10）⇒ 扫描面疑似失明`);

// ---- ④⑪a 真仓扫描：**逐窗** RM 归零覆盖 + 逐交互面焦点可见（T1d-M04） ----
// P0 子窗 CSS 按需（6a8f02b）曾把全窗 RM 归零段搬进只主窗加载的 main-pages.css，
// 四子窗动效归零整段失效（可达动效 32/19/14/16 条照播），而旧判据「main+pages 合并判」
// 照绿——合并集把「搬错文件」读成「已覆盖」。归零覆盖面是**每扇窗**的属性：
// 逐窗解析各自 <link> 的 CSS 合并集判，「归零段搬错文件 / 子窗漏挂 CSS」都会红。
// 焦点同理：旧判据只要合并集里存在任一条 :focus-visible 就恒过；现在每个交互面
// 都要在该窗合并 CSS 里解析出可见指示（自选择器或裸 :focus-visible，outline:none
// 且无替代指示不算），少一个面就红。
{
  const cssCache = new Map();
  const loadCss = (f) => {
    if (!cssCache.has(f)) cssCache.set(f, readFileSync(join(SRC, 'styles', f), 'utf8'));
    return cssCache.get(f);
  };
  let windowCount = 0;
  let focusSurfaceChecks = 0;
  let focusSurfaceProblems = 0;
  for (const p of htmlFiles) {
    const html = read(p);
    const links = styleLinks(html).map((h) => h.split('/').pop());
    if (links.length === 0) {
      g.fail(`${rel(p)}：没有解析到任何 stylesheet link（窗体 CSS 覆盖判定失明）`);
      continue;
    }
    windowCount++;
    const merged = links.map(loadCss).join('\n');
    for (const v of rmViolations(merged)) {
      g.fail(`${rel(p)}：${v}（该窗加载 ${links.join(', ')}）`);
    }
    for (const surface of FOCUS_SURFACES) {
      focusSurfaceChecks++;
      if (!focusVisibleFor(merged, surface.sel).visible) {
        focusSurfaceProblems++;
        g.fail(`${rel(p)}：交互面 ${surface.sel}（${surface.why}）在合并 CSS（${links.join(', ')}）里没有可判红的焦点指示`);
      }
    }
  }
  // preview 子窗退役后主窗+3 子窗 = 4 份（2026-10-13）
  if (windowCount < 4) g.fail(`逐窗 RM 判定只覆盖 ${windowCount} 份 HTML（< 4）⇒ 语料失明`);
  if (focusSurfaceChecks < 60) g.fail(`逐交互面焦点判定只覆盖 ${focusSurfaceChecks} 面（< 60）⇒ 语料失明`);
  if (focusSurfaceProblems === 0 && focusSurfaceChecks >= 60) {
    g.ok(`⑪a 逐交互面焦点可见：${windowCount} 扇窗 × ${FOCUS_SURFACES.length} 面 = ${focusSurfaceChecks} 面全部解析出可见焦点指示`);
  }
}

// ---- ⑤⑥ 真仓扫描 ----
{
  // ⑤ 可选链重复注册（剥注释）
  const strip = (t) => blankNonCode(t, 'js', { keepStrings: true });
  let regSites = 0;
  for (const [p, text, isJs] of sources) {
    if (!isJs) continue;
    const clean = strip(text);
    regSites += [...clean.matchAll(RE_OPT_CHAIN_REG)].length;
    for (const d of dupOptChainRegistrations(clean)) g.fail(`${rel(p)}：同元素同事件重复注册 ${d}`);
  }
  if (regSites < 3) g.fail(`可选链注册命中 ${regSites} 处（< 3）⇒ 扫描面疑似失明`);

  // ⑥ 子窗脚本不得依赖 window.app（子窗 = 非 index.html 的 HTML 所挂脚本）
  const subScriptNames = new Set();
  for (const p of htmlFiles) {
    if (p.endsWith('index.html')) continue;
    const t = readFileSync(p, 'utf8');
    for (const m of t.matchAll(/src="([^"]*\.js)"/g)) subScriptNames.add(m[1].split('/').pop());
  }
  let subChecked = 0;
  for (const [p, text] of sources) {
    const base = p.split(/[\\/]/).pop();
    if (!subScriptNames.has(base) || base === 'tauri-api.js' || base === 'ds.js') continue; // 适配层/公共件除外
    subChecked++;
    for (const v of windowAppViolations(strip(text))) g.fail(`${rel(p)}：子窗脚本依赖 window.app ${v}（子窗不加载 app.js，恒 undefined）`);
  }
  if (subChecked < 3) g.fail(`子窗脚本扫描面 ${subChecked} 个（< 3）⇒ 清单/语料失明`);
}

// T1d-K01：采集面地板——jsFiles 塌缩（scripts/ 或 vendor/ 改名）时其余断言全是空集假绿
if (jsFiles.length < JS_CORPUS_FLOOR) {
  g.fail(`前端 js 语料只有 ${jsFiles.length} 个（< ${JS_CORPUS_FLOOR}）⇒ 采集面塌陷（scripts/** + vendor/** 递归现算），拒绝判绿`);
}

// ---------- C-06（F4a1-L14）：自写 keydown 必须挡按键连发 ----------
// 长按一个键会连发 keydown（`e.repeat === true`）。绑在「Enter/Space 触发动作」上的
// 处理器若不挡，一次物理按键会被放大成连续多次动作（折叠行开→关→开、抽屉反复收起）。
// 本组只认**触发动作**的那类 keydown（键位判定含 Enter / Space），方向键导航类
// （ArrowUp/ArrowDown 移动焦点）连发是期望行为，不在本组判据面。
{
  const RE_KEYDOWN_HANDLER = /addEventListener\(\s*['"]keydown['"]\s*,\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{/g;
  const RE_ACTION_KEY = /\be\.key\s*===?\s*['"](?:Enter| |Spacebar)['"]|\be\.code\s*===?\s*['"](?:Enter|Space)['"]/;
  // 「触发动作」的判据：Enter/Space 分支里调用了某个**非 e.* 的**函数。
  // 只做 preventDefault / stopPropagation 的（xtable 的列宽手柄：Enter/Space 就地吞掉，
  // 防冒泡到表头排序）不触发动作，长按连发无害 —— 那种不该被这条判据拉进来。
  const RE_ACTION_CALL = /(?<![.\w$])(?:[A-Za-z_$][\w$]*)\s*\(/;
  const RE_REPEAT_GUARD = /if\s*\(\s*e\.repeat\s*\)\s*return\s*;/;
  const missing = [];
  let actionHandlers = 0;
  for (const [p, text] of sources) {
    const stripped = blankNonCode(text, 'js', { keepStrings: true });
    for (const m of stripped.matchAll(RE_KEYDOWN_HANDLER)) {
      // 取 handler 体：从 `{` 起做括号配对（本仓写法都是单行箭头函数 + 块）。
      const open = stripped.indexOf('{', m.index + m[0].length - 1);
      if (open < 0) continue;
      let depth = 0;
      let end = open;
      for (let i = open; i < stripped.length; i++) {
        const c = stripped[i];
        if (c === '{') depth++;
        else if (c === '}') {
          depth--;
          if (depth === 0) { end = i; break; }
        }
      }
      const body = stripped.slice(open, end + 1);
      if (!RE_ACTION_KEY.test(body)) continue; // 不是「按键触发动作」的那类
      // 「触发动作」的判据：**Enter/Space 那一支**里存在非 e.* 的函数调用。
      // 逐个 e.key 判断取其体（花括号分支取块内；无花括号早退则取该 if 之后到下一个 if 之前）：
      // ① `if (e.key === 'Enter' || ...) { e.preventDefault(); doThing(); }`（花括号分支）；
      // ② `if (e.key !== 'Enter' && ...) return; doThing();`（无花括号早退）。
      // 只看 Enter/Space 那一支：xtable 的列宽手柄 Enter/Space 只 preventDefault（不触发动作），
      // 而 Arrow 分支有 applyColWidth —— 方向键连发步进是期望行为，不该被拉进来。
      // 把 e.preventDefault( / e.stopPropagation( 换成不可能匹配的占位（__EP__）——
      // 换成 `e_(` 仍会被「非 e.* 的调用」判据当成一次调用。
      const withoutEP = body.replace(/\be\s*\.\s*(?:preventDefault|stopPropagation)\s*\(\s*\)/g, '__EP__');
      let actionBranch = '';
      const keyIfs = [...withoutEP.matchAll(/if\s*\(([^)]*e\.key[^)]*)\)/g)];
      for (const kif of keyIfs) {
        const cond = kif[1];
        if (!/['"](?:Enter| |Spacebar)['"]/.test(cond)) continue; // 不是 Enter/Space 那一支
        const after = withoutEP.slice(kif.index + kif[0].length);
        const braceAt = after.indexOf('{');
        const nextIfAt = after.search(/\bif\s*\(/);
        if (braceAt >= 0 && (nextIfAt < 0 || braceAt < nextIfAt)) {
          // 花括号分支：取块内
          let d = 0;
          for (let i = braceAt; i < after.length; i++) {
            if (after[i] === '{') d++;
            else if (after[i] === '}') { d--; if (d === 0) { actionBranch = after.slice(braceAt + 1, i); break; } }
          }
        } else {
          // 无花括号早退：取该 if 之后到下一个 if 之前
          actionBranch = nextIfAt < 0 ? after : after.slice(0, nextIfAt);
        }
        if (actionBranch) break;
      }
      if (!actionBranch) continue; // 取不到 Enter/Space 分支 ⇒ 不在本组判据面
      const branchCall = RE_ACTION_CALL.exec(actionBranch);
      if (!branchCall) continue; // 分支里没有非 e.* 的调用 ⇒ 不是触发动作
      actionHandlers++;
      if (!RE_REPEAT_GUARD.test(body)) {
        missing.push(`${rel(p)}：自写 keydown 触发动作（Enter/Space）但没有 \`if (e.repeat) return;\` 守卫 ⇒ 长按会连发`);
      }
    }
  }
  if (actionHandlers < 3) {
    g.fail(`C-06 动作型 keydown 只认出 ${actionHandlers} 个（< 3）⇒ 扫描面疑似失明`);
  }
  if (missing.length) {
    for (const m of missing) g.fail(m);
  } else {
    g.ok(`C-06 动作型 keydown 全部挡了按键连发（${actionHandlers} 处）`);
  }
}

console.log(
  `\n扫描：${sources.length} 个源文件（js 语料 ${jsFiles.length} 个） · 勾选框模板 ${checkboxSites} 处 · 提示宿主 ${liveHosts} 处 · data-tip ${tipSites} 处 · 可访问名过渡表 ${NAME_TRANSITION.length}/${NAME_DEBT_CAP} 条`,
);
if (fail > 0) {
  console.error(`check-a11y: 正向对照自检 ${fail} 处失败（判定器失效，本门禁不可信）`);
  process.exit(1);
}
g.finish('check-a11y: 全部通过');
