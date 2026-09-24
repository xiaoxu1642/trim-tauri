// check-optimizer-dynamic.mjs —— 「dynamic 优化项的 id ⇄ 控件 ⇄ 参数」三方对拍（审查 v2-M10）
//
// 为什么需要这条门禁：v2-M10 的缺陷形态是「界面可见可点、后端永远报错」——
// 数据层把 perf_wu_pause 标成 `dynamic: true`，后端 is_dynamic 分支要求 `p.days`，
// 而前端把所有 dynamic 项一刀切画成内存 GB 下拉、只发 `{gb}`。
// 三方各改一处都不会有编译错误、不会有测试红，只有用户看见「这个优化项永远失败」。
// 唯一能长期钉住它的是静态对拍：**三份集合必须一致**。
//
// 五条断言：
//   A1 数据层 `dynamic:true` 的 id 集合 == optimizer.js 的 DYNAMIC_CONTROLS 键集合（双向差集）
//   A2 每个 dynamic id 在 Rust 的 is_dynamic 分支里有 `option_id == "<id>"` 分支
//   A3 前端 paramKey == 该分支读的 `p.<字段>`，且字段存在于 RunParams
//   A4 暂停天数上限两侧一致（JS WU_PAUSE_MAX_DAYS == Rust 同名常量）
//   A5 前端不得再按 `dynamic` 一刀切：`.opt-mem-select` 必须归零、执行参数走 dynamicParams、
//      批量入口不得再发裸 `{}`（那正是 v2-M10 的第二条失法路径）
//
// 用法：node tools/check-optimizer-dynamic.mjs
//   退出码 0 = 五条全绿；1 = 任一不符（无「只警告」档）。

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const R = (rel) => readFileSync(join(REPO_ROOT, ...rel.split('/')), 'utf8');

const dataJson = R('src-tauri/data/optimizer-runtime.json');
const jsOpt = R('src/scripts/optimizer.js');
const rustOpt = R('src-tauri/src/commands/optimizer.rs');

let fail = 0;
function check(ok, name, detail) {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' —— ' + detail : ''}`);
  if (!ok) fail++;
}

/** 从 `const NAME = {` 起按括号配平切出对象字面量（比按行猜 `};` 稳） */
function objectLiteral(src, declRegex) {
  const m = declRegex.exec(src);
  if (!m) return null;
  const start = src.indexOf('{', m.index);
  let depth = 0;
  for (let i = start; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) return src.slice(start, i + 1); }
  }
  return null;
}

/** 取对象字面量的**顶层**键：按花括号深度扫，depth===1 时出现的 `ident:` 才是顶层键。
 *  不能按缩进猜（本仓 optimizer.js 的表在 IIFE 里、键是 4 空格；写死 2 空格会解析出空集合，
 *  于是 A1 把"前端缺全部登记"报成缺陷——门禁自己误报比漏报更糟，它会让人去改对的代码）。 */
function topLevelKeys(lit) {
  const out = [];
  let depth = 0;
  for (const rawLine of lit.split(/\r?\n/)) {
    // 字符串字面量里的花括号不参与配平
    const line = rawLine.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""');
    if (depth === 1) {
      const m = /^\s*([A-Za-z0-9_]+)\s*:/.exec(line);
      if (m) out.push(m[1]);
    }
    for (const ch of line) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
  }
  return out;
}

// ---- A1：数据层 dynamic 集合 ⇄ 前端分派表键集合 ----
let options = null;
try { options = JSON.parse(dataJson); } catch { /* 下面判红 */ }
if (!Array.isArray(options)) {
  check(false, 'A1. 数据层 dynamic 集合 ⇄ 前端分派表', 'optimizer-runtime.json 读不到或不是数组');
} else {
  const dynIds = options.filter((o) => o && o.dynamic === true).map((o) => o.id).sort();
  const table = objectLiteral(jsOpt, /const DYNAMIC_CONTROLS\s*=/);
  if (!table) {
    check(false, 'A1. 数据层 dynamic 集合 ⇄ 前端分派表', 'optimizer.js 里找不到 const DYNAMIC_CONTROLS');
  } else {
    // 只取对象字面量**顶层**的 key（按深度扫，不猜缩进）
    const jsIds = topLevelKeys(table).sort();
    const missing = dynIds.filter((i) => !jsIds.includes(i));
    const extra = jsIds.filter((i) => !dynIds.includes(i));
    const a1Pass = missing.length === 0 && extra.length === 0 && dynIds.length > 0;
    check(
      a1Pass,
      `A1. 数据层 dynamic 集合 ⇄ 前端分派表（各 ${dynIds.length} / ${jsIds.length}）`,
      a1Pass ? '' : dynIds.length === 0 ? '数据层一个 dynamic 项都没有——是否整份数据被换掉'
        : missing.length ? `前端缺控件登记：${missing.join(', ')}`
          : `前端表里有数据层不存在的死条目：${extra.join(', ')}`
    );

    // ---- A2 / A3：Rust 分支与字段名 ----
    const dynBlockStart = rustOpt.indexOf('let is_dynamic');
    const branchIds = dynBlockStart < 0 ? [] :
      [...rustOpt.slice(dynBlockStart, dynBlockStart + 4000)
        .matchAll(/option_id == "([^"]+)"/g)].map((m) => m[1]);
    check(
      dynBlockStart >= 0 && branchIds.length > 0 && dynIds.every((i) => branchIds.includes(i)),
      `A2. 每个 dynamic id 在 Rust is_dynamic 分支有对应判断（Rust 侧 ${branchIds.join(', ') || '无'}）`,
      dynBlockStart < 0 ? 'optimizer.rs 里找不到 let is_dynamic' : ''
    );

    const runParams = objectLiteral(rustOpt, /pub struct RunParams/) || '';
    let fieldOk = true;
    const lines = [];
    for (const id of jsIds) {
      const block = objectLiteral(table, new RegExp(`^\\s*${id}: \\{`, 'm'));
      const pm = block && /paramKey: '([^']+)'/.exec(block);
      if (!pm) { fieldOk = false; lines.push(`${id}: 缺 paramKey`); continue; }
      const key = pm[1];
      // 该 id 的 Rust 分支体内必须读 p.<key>
      const idAt = rustOpt.indexOf(`option_id == "${id}"`, Math.max(dynBlockStart, 0));
      const body = idAt < 0 ? '' : rustOpt.slice(idAt, idAt + 1200);
      const readsOwn = new RegExp(`p\\.${key}\\b`).test(body);
      const declared = new RegExp(`(^|\\n)\\s*(pub )?${key}:\\s*Option<`).test(runParams);
      if (!readsOwn || !declared) {
        fieldOk = false;
        lines.push(`${id}: paramKey=${key} 但 ${!readsOwn ? 'Rust 分支没读 p.' + key : !declared ? 'RunParams 里没有 ' + key : ''}`);
      }
    }
    check(fieldOk, `A3. 前端 paramKey ⇄ Rust 读取字段 ⇄ RunParams 声明（${jsIds.length} 项）`,
      fieldOk ? '' : lines.join(' / '));

    // ---- A4：暂停天数上限两侧一致 ----
    const jsMax = /const WU_PAUSE_MAX_DAYS\s*=\s*(\d+)/.exec(jsOpt);
    const rustMax = /const WU_PAUSE_MAX_DAYS:\s*\w+\s*=\s*(\d+)/.exec(rustOpt);
    check(
      !!(jsMax && rustMax) && jsMax[1] === rustMax[1],
      `A4. WU_PAUSE_MAX_DAYS 两侧一致（JS ${jsMax ? jsMax[1] : '缺'} / Rust ${rustMax ? rustMax[1] : '缺'}）`,
      jsMax && rustMax && jsMax[1] !== rustMax[1] ? '只改一侧会让前端给出的天数被后端判成越界' : ''
    );
  }
}

// ---- A5：前端不得再按 dynamic 一刀切画内存下拉、批量不得发裸 {} ----
const staleSelectClass = (jsOpt.match(/opt-mem-select/g) || []).length;
const usesDynSelect = jsOpt.includes("querySelector('.opt-dyn-select')");
const usesDynParams = jsOpt.includes('dynamicParams(') && jsOpt.includes('const dyn = DYNAMIC_CONTROLS[o.id]');
const bareBatchParams = (jsOpt.match(/runOptionActive\(\{\}/g) || []).length;
const a5Pass = staleSelectClass === 0 && usesDynSelect && usesDynParams && bareBatchParams === 0;
check(
  a5Pass,
  `A5. 前端按 id 取控件/参数（.opt-mem-select ${staleSelectClass} 处、裸 {} 批量 ${bareBatchParams} 处）`,
  a5Pass ? '' // 全绿时不得再落进下面的原因链——原先收尾分支没有守卫，✓ 也会打印「仍在发空参数对象」
    : staleSelectClass ? '仍按单一内存类名找下拉'
      : !usesDynSelect ? '弹窗没有统一走 .opt-dyn-select'
        : !usesDynParams ? '没走 DYNAMIC_CONTROLS / dynamicParams 分派'
          : '批量入口仍在发空参数对象'
);

console.log(`\n${fail === 0 ? '门禁通过' : `${fail} 项未通过`}`);
process.exit(fail === 0 ? 0 : 1);
