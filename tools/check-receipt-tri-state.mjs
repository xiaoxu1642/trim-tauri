'use strict';
// tools/check-receipt-tri-state.mjs —— 前端回执三态：失败不得被念成成功
//
// 出处：2026-10-27 全仓重审 P1（F4b-M10 / M12 / M14 / M17 / M18）。
// 病根一句话：后端大量「拒收」出口是 `Ok({ success: false, message })` —— Promise 照常 resolve，
// 于是 `await` 不抛错、`if (resp && resp.success)` 之后的 else 缺失就等于「失败无声」。
// 五条具体形态：
//   M10  丢包采样：失败时只保留上一拍陈旧值当现行（用户在界面上看到的是旧数字）。
//   M12  批量执行：`batchRunning = true` 之后没有 finally，一处抛错把批量入口永久焊死。
//   M14  密钥「清空」走的是空串落盘，破坏面比「覆盖」更大，却零确认。
//   M17  时长参数：绑定被删掉，演示分支读它时抛 ReferenceError。
//   M18  三处写侧（保存 / 删除 / 清空历史）不读回执就报「已保存 / 已删除 / 已清空」。
//
// 判据面（逐条登记式，每条一个「必须存在的形态」+ 一个正向对照）：
//   判据只看**源码形态**，不跑浏览器 —— 本仓前端没有 JS 单测装置，
//   行为验收只能落成源码形状门禁 + 逐文件基线（与 check-confirm-danger 同款做法）。
//   正向对照必须能把「修好的形态」与「修坏的形态」区分开，否则下面这些绿是空绿。
//
// 用法：node tools/check-receipt-tri-state.mjs

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { gate } from './lib/gate.mjs';

const ROOT = process.cwd();
const g = gate(import.meta.url);

const read = (rel) => {
  const abs = join(ROOT, rel);
  return existsSync(abs) ? readFileSync(abs, 'utf8') : null;
};

/** 取某个具名函数所在的行段（到下一个同形函数声明为止）。 */
const funcBlock = (src, name) => {
  const lines = src.split('\n');
  const re = new RegExp(`^\\s*(async\\s+)?function\\s+${name}\\s*\\(`);
  const start = lines.findIndex(l => re.test(l));
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*(async\s+)?function\s+\w+\s*\(/.test(lines[i])) { end = i; break; }
  }
  return lines.slice(start, end).join('\n');
};

/** 从某个下标起向后看 N 行。 */
const windowAfter = (src, needle, span) => {
  const lines = src.split('\n');
  const i = lines.findIndex(l => l.includes(needle));
  if (i < 0) return null;
  return lines.slice(i, i + span).join('\n');
};

/** 找出全部出现某 needle 的下标。 */
const allIndexes = (src, needle) => {
  const out = [];
  const lines = src.split('\n');
  lines.forEach((l, i) => { if (l.includes(needle)) out.push(i); });
  return out;
};

const CASES = [];
const addCase = (id, ok) => { CASES.push({ id, ok }); };

// ---------- M10：丢包采样失败不得沿用上一拍 ----------
{
  const src = read('src/scripts/realtime.js');
  if (!src) {
    g.fail('M10：src/scripts/realtime.js 不存在（判定对象缺失）');
  } else {
    const block = funcBlock(src, 'lossOnce') || '';
    const good = /if\s*\(\s*resp\s*&&\s*resp\.success\s*\)/.test(block)
      && /\}\s*else\s*\{/.test(block)
      && /lossRate:\s*null/.test(block);
    const bad = `async function lossOnce() {\n  const resp = await window.api.realtime.loss();\n  if (resp && resp.success) {\n    state.loss = { lossRate: 1 };\n  }\n}`;
    const goodSample = `async function lossOnce() {\n  const resp = await window.api.realtime.loss();\n  if (resp && resp.success) {\n    state.loss = { lossRate: 1 };\n  } else {\n    state.loss = { lossRate: null };\n  }\n}`;
    const judge = (text) => /if\s*\(\s*resp\s*&&\s*resp\.success\s*\)/.test(text)
      && /\}\s*else\s*\{/.test(text) && /lossRate:\s*null/.test(text);
    if (!judge(goodSample) || judge(bad)) {
      g.fail('M10 正向对照失败：丢包三态判定器失真（必须能把「有 else 且置 null」与「只有 if」分开）');
    }
    if (!good) {
      g.fail('M10：realtime.js 的 lossOnce 缺失败态落地（无 else 分支 / 未把 lossRate 置 null）⇒ 上一拍的陈旧丢包率会被当现行');
    } else {
      g.ok('M10：丢包采样失败有独立落地（lossRate 置 null，不再沿用上一拍）');
    }
    addCase('M10', good);
  }
}

// ---------- M17：时长参数必须先绑定再进对象 ----------
{
  const src = read('src/scripts/diskbench.js');
  if (!src) {
    g.fail('M17：src/scripts/diskbench.js 不存在（判定对象缺失）');
  } else {
    const bound = /const\s+duration\s*=\s*pickTier\(/.test(src);
    const inline = /duration:\s*pickTier\(/.test(src);
    const judge = (text) => /const\s+duration\s*=\s*pickTier\(/.test(text) && !/duration:\s*pickTier\(/.test(text);
    const goodSample = 'const duration = pickTier(x, [4, 8, 16], 8, "时长");\nconst options = { duration };';
    const badSample = 'const options = { duration: pickTier(x, [4, 8, 16], 8, "时长") };';
    if (!judge(goodSample) || judge(badSample)) {
      g.fail('M17 正向对照失败：时长绑定判定器失真（必须能把「先绑定」与「内联」分开）');
    }
    if (!bound || inline) {
      g.fail('M17：diskbench.js 的时长参数没有独立绑定（仍内联在 options 里）⇒ 演示分支读不到它会抛 ReferenceError');
    } else {
      g.ok('M17：时长参数已独立绑定（演示分支不再读到未定义变量）');
    }
    addCase('M17', bound && !inline);
  }
}

// ---------- M18：三处写侧必须读回执 ----------
{
  const src = read('src/scripts/diskbench.js');
  if (!src) {
    g.fail('M18：src/scripts/diskbench.js 不存在（判定对象缺失）');
  } else {
    const sites = ['benchHistory.add(', 'benchHistory.delete(', 'benchHistory.clear('];
    const judge = (text, needle) => {
      const w = windowAfter(text, needle, 24);
      return !!w && /\.success\s*===\s*false/.test(w);
    };
    const goodSample = 'await window.api.benchHistory.add(x);\nif (!receipt || receipt.success === false) { return; }';
    const badSample = 'await window.api.benchHistory.add(x);\nbtn.remove();';
    if (!judge(goodSample, 'benchHistory.add(') || judge(badSample, 'benchHistory.add(')) {
      g.fail('M18 正向对照失败：写侧回执判定器失真（必须能把「读回执」与「不读回执」分开）');
    }
    let bad = 0;
    for (const s of sites) {
      if (!judge(src, s)) {
        g.fail(`M18：${s} 之后没有读回执的分支 ⇒ 失败会被念成「已保存 / 已删除 / 已清空」`);
        bad++;
      }
    }
    if (bad === 0) g.ok('M18：历史记录的三处写侧都读了回执');
    addCase('M18', bad === 0);
  }
}

// ---------- M12：批量执行的上锁必须在 finally 里放 ----------
{
  const src = read('src/scripts/optimizer.js');
  if (!src) {
    g.fail('M12：src/scripts/optimizer.js 不存在（判定对象缺失）');
  } else {
    /**
     * 判据必须打在语义差上：**锁点与解锁点必须同属一个函数，且解锁点落在 finally 之后**。
     * 只判「附近出现过 finally」会被「函数 A 的 finally + 函数 B 的解锁」凑成假绿
     * （首版就这么栽了：把 finally 里的解锁删掉，门禁照样绿）。
     */
    const judge = (text) => {
      const lines = text.split('\n');
      const at = lines.findIndex(l => l.includes('batchRunning = true;'));
      if (at < 0) return false;
      let start = at;
      while (start > 0 && !/^\s*(async\s+)?function\s+\w+\s*\(/.test(lines[start])) start--;
      let end = at;
      while (end < lines.length && !/^\s*(async\s+)?function\s+\w+\s*\(/.test(lines[end])) end++;
      const seg = lines.slice(start, end);
      const lockAt = seg.findIndex(l => l.includes('batchRunning = true;'));
      const finallyAt = seg.findIndex((l, i) => i > lockAt && /finally\s*\{/.test(l));
      const unlockAt = seg.findIndex((l, i) => i > lockAt && /batchRunning\s*=\s*false/.test(l));
      return finallyAt >= 0 && unlockAt > finallyAt;
    };
    const goodSample = 'async function runSelected() {\n  batchRunning = true;\n  try {\n    await x();\n  } finally {\n    batchRunning = false;\n  }\n}';
    const badSample = 'async function runSelected() {\n  batchRunning = true;\n  await x();\n  batchRunning = false;\n}';
    const badSample2 = 'async function runSelected() {\n  batchRunning = true;\n  try {\n    await x();\n  } finally {\n    cleanup();\n  }\n}';
    if (!judge(goodSample) || judge(badSample) || judge(badSample2)) {
      g.fail('M12 正向对照失败：批量锁判定器失真（必须能把「finally 内解锁」「顺序解锁」「finally 不解锁」三种形态分开）');
    }
    // 逐个上锁点判定：按函数段切开，函数内必须自带 finally + 解锁
    const lines = src.split('\n');
    const lockLines = allIndexes(src, 'batchRunning = true;');
    let bad = 0;
    for (const i of lockLines) {
      let start = i;
      while (start > 0 && !/^\s*(async\s+)?function\s+\w+\s*\(/.test(lines[start])) start--;
      let end = i;
      while (end < lines.length && !/^\s*(async\s+)?function\s+\w+\s*\(/.test(lines[end])) end++;
      const seg = lines.slice(start, end);
      const lockAt = seg.findIndex(l => l.includes('batchRunning = true;'));
      const finallyAt = seg.findIndex((l, k) => k > lockAt && /finally\s*\{/.test(l));
      const unlockAt = seg.findIndex((l, k) => k > lockAt && /batchRunning\s*=\s*false/.test(l));
      if (!(finallyAt >= 0 && unlockAt > finallyAt)) {
        g.fail(`M12：optimizer.js 第 ${i + 1} 行上锁所在函数没有 finally 放锁 ⇒ 循环后段抛错会把批量入口永久焊死`);
        bad++;
      }
    }
    if (lockLines.length < 2) {
      g.fail(`M12：只认出 ${lockLines.length} 处批量上锁点（预期两处）⇒ 判据形状或文件漂移`);
      bad++;
    }
    if (bad === 0) g.ok('M12：两处批量入口的锁都在同一函数的 finally 里放');
    addCase('M12', bad === 0);
  }
}

// ---------- M14：清空密钥也要走确认件 ----------
{
  const src = read('src/scripts/models-window.js');
  if (!src) {
    g.fail('M14：src/scripts/models-window.js 不存在（判定对象缺失）');
  } else {
    // 判据必须同时钉住三件事：清空态的**真实定义**、它**进了条件**、确认件**有清空分支**。
    // 只查「文件里出现过 clearingKey」会被 `const clearingKey = false` 这种空壳骗过。
    const judge = (text) => /const\s+clearingKey\s*=\s*!!prevKey\s*&&\s*!newKey/.test(text)
      && /\(clearingKey\s*\|\|/.test(text)
      && /okText:\s*'清除密钥'/.test(text);
    const goodSample = "const clearingKey = !!prevKey && !newKey;\nif (prevKey && (clearingKey || newKey !== prevKey)) {\n  go = await selfConfirm({ okText: '清除密钥' });\n}";
    const badSample = "const clearingKey = false;\nif (prevKey && newKey && newKey !== prevKey) {\n  go = await selfConfirm({ okText: '覆盖保存' });\n}";
    if (!judge(goodSample) || judge(badSample)) {
      g.fail('M14 正向对照失败：清空密钥护栏判定器失真（必须能把「清空也确认」与「只确认覆盖」分开）');
    }
    if (!judge(src)) {
      g.fail('M14：models-window.js 的清空密钥支没有确认件（或清空态判定是空壳）⇒ 清空（空串落盘）比覆盖破坏更大却零护栏');
    } else {
      g.ok('M14：清空密钥也走红色确认件');
    }
    addCase('M14', judge(src));
  }
}

if (!g.skipUnlessPresent(join(ROOT, 'src', 'scripts', 'optimizer.js'), 'src/scripts（本门禁的判定对象）')) g.finish();

const failed = CASES.filter(c => !c.ok).length;
if (failed > 0) g.fail(`回执三态判据：${failed} 条不达标（共 ${CASES.length} 条）`);
else g.ok(`回执三态判据：${CASES.length} 条全部达标`);

g.finish('check-receipt-tri-state: 全部通过');
