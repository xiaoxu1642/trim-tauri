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
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';
import { blankNonCode } from './lib/src-scan.mjs';

// 仓根由本文件位置推出，不用 `process.cwd()`：换目录单跑会假红（T1b-L01）。
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
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

// ---------- P0-F4a1-M15：低危常规项永久删必须有确认 ----------
{
  const src = read('src/scripts/cleanup.js');
  const html = read('src/index.html');
  if (!src || !html) {
    g.fail('F4a1-M15：cleanup.js 或 index.html 不存在（判定对象缺失）');
  } else {
    const clean = blankNonCode(src, 'js', { keepStrings: true });
    const block = funcBlock(clean, 'confirmCleanPlan') || '';
    const judge = (text, markup) => {
      const fn = funcBlock(text, 'confirmCleanPlan') || '';
      return /const\s+lowRisk\s*=/.test(fn)
        && /r\.id\s*!==\s*RECYCLE_ID/.test(fn)
        && /!FILECLEAN_IDS\.includes\(r\.id\)/.test(fn)
        && /confirmWarning\(\s*'永久删除确认'/.test(fn)
        && /不进入回收站/.test(fn)
        && /if\s*\(!ok\)\s*return null;/.test(fn)
        && /id="cleanupPermanentHint"[^>]*>[^<]*不进入回收站/.test(markup);
    };
    const goodSample = [
      'async function confirmCleanPlan() {',
      "  const lowRisk = selectedWithResultIds().filter(r => r.id !== RECYCLE_ID && !FILECLEAN_IDS.includes(r.id));",
      "  const ok = await window.app?.confirmWarning('永久删除确认', '这些项目会直接永久删除，不进入回收站。');",
      '  if (!ok) return null;',
      '}',
    ].join('\n');
    const badSample = [
      'async function confirmCleanPlan() {',
      "  const lowRisk = selectedWithResultIds().filter(r => r.id !== RECYCLE_ID && !FILECLEAN_IDS.includes(r.id));",
      '  return lowRisk;',
      '}',
    ].join('\n');
    const goodHtml = '<div id="cleanupPermanentHint">常规清理项会直接永久删除，不进入回收站。</div>';
    const badHtml = '<div id="cleanupPermanentHint">常规清理项。</div>';
    if (!judge(goodSample, goodHtml) || judge(badSample, badHtml)) {
      g.fail('F4a1-M15 正向对照失败：永久删确认判定器失真（必须能把「有确认+页面告知」与「零确认」分开）');
    }
    const ok = judge(clean, html);
    if (!ok) {
      g.fail('F4a1-M15：低危常规项缺永久删确认/页面缺告知，或未排除文件清理项');
    } else {
      g.ok('F4a1-M15：低危常规项永久删有确认，文件清理项被排除，页面有「不进入回收站」提示');
    }
    addCase('F4a1-M15', ok);
  }
}

// ---------- P0-A2-M01：startup.remove 回执与逐项 status 必须都判 ----------
{
  const src = read('src/scripts/startup.js');
  if (!src) {
    g.fail('A2-M01：src/scripts/startup.js 不存在（判定对象缺失）');
  } else {
    const clean = blankNonCode(src, 'js', { keepStrings: true });
    const helper = funcBlock(clean, 'startupRemoveOutcome') || '';
    const lines = clean.split('\n');
    const removeSites = allIndexes(clean, 'window.api.startup.remove([it])');
    const checkedSites = removeSites.length === 2 && removeSites.every((at) => {
      const line = lines[at];
      const after = lines.slice(at + 1, at + 10).join('\n');
      return /const\s+resp\s*=\s*await\s+window\.api\.startup\.remove\(\[it\]\);/.test(line)
        && /const\s+removed\s*=\s*startupRemoveOutcome\(resp,\s*it\)/.test(after)
        && /if\s*\(!removed\.ok\)/.test(after)
        && /continue;/.test(after);
    });
    const judge = (text) => {
      const block = funcBlock(text, 'startupRemoveOutcome') || '';
      const body = text.split('\n');
      const sites = allIndexes(text, 'window.api.startup.remove([it])');
      return /resp\.success\s*!==\s*true/.test(block)
        && /Array\.isArray\(data\.results\)/.test(block)
        && /hit\.status\s*!==\s*'ok'/.test(block)
        && sites.length === 2
        && sites.every((at) => /const\s+resp\s*=\s*await\s+window\.api\.startup\.remove\(\[it\]\);/.test(body[at]));
    };
    const goodSample = [
      'function startupRemoveOutcome(resp, item) {',
      "  if (!resp || resp.success !== true) return { ok: false };",
      '  const data = resp.data || {};',
      '  const results = Array.isArray(data.results) ? data.results : [];',
      "  if (hit.status !== 'ok') return { ok: false };",
      '}',
      'async function enforceStartupDefend() {',
      '  const resp = await window.api.startup.remove([it]);',
      '  const resp = await window.api.startup.remove([it]);',
      '}',
    ].join('\n');
    const badSample = [
      'function startupRemoveOutcome(resp, item) { return { ok: true }; }',
      'async function enforceStartupDefend() {',
      '  await window.api.startup.remove([it]);',
      '  await window.api.startup.remove([it]);',
      '}',
    ].join('\n');
    if (!judge(goodSample) || judge(badSample)) {
      g.fail('A2-M01 正向对照失败：startup.remove 回执判定器失真（必须能把「读 success+status」与「只 await」分开）');
    }
    const ok = judge(clean) && checkedSites;
    if (!ok) {
      g.fail('A2-M01：startup.remove 失败回执或逐项 status 未判，失败项仍可能进 autoDeleted / 黑名单');
    } else {
      g.ok('A2-M01：startup.remove 两处删除入口都逐项判 success/status，失败项保留');
    }
    addCase('A2-M01', ok);
  }
}

// ---------- P0-F4c-M08：字体保存与删除都必须读 resolve 的 success:false ----------
{
  const src = read('src/scripts/fontmanager.js');
  if (!src) {
    g.fail('F4c-M08：src/scripts/fontmanager.js 不存在（判定对象缺失）');
  } else {
    const clean = blankNonCode(src, 'js', { keepStrings: true });
    const saveBlock = funcBlock(clean, 'saveConfig') || '';
    const removalWindow = windowAfter(clean, 'window.api.fonts.removeImported()', 35) || '';
    const judge = (text) => {
      const save = funcBlock(text, 'saveConfig') || '';
      const remove = windowAfter(text, 'window.api.fonts.removeImported()', 35) || '';
      return /resp\.success\s*!==\s*true/.test(save)
        && /if\s*\(resp\s*&&\s*resp\.success\)/.test(remove)
        && /\}\s*else\s*\{/.test(remove);
    };
    const goodSample = [
      'async function saveConfig() {',
      '  const resp = await window.api.fonts.saveConfig(settings);',
      "  if (!resp || resp.success !== true) throw new Error('失败');",
      '}',
      'window.api.fonts.removeImported()',
      'if (resp && resp.success) { ok(); } else { fail(); }',
    ].join('\n');
    const badSample = [
      'async function saveConfig() {',
      '  await window.api.fonts.saveConfig(settings);',
      '}',
      'window.api.fonts.removeImported()',
      'toast.success();',
    ].join('\n');
    if (!judge(goodSample) || judge(badSample)) {
      g.fail('F4c-M08 正向对照失败：字体写配置判定器失真（必须能把「判 success」与「只 await」分开）');
    }
    const ok = judge(clean) && /resp\.success\s*!==\s*true/.test(saveBlock) && /if\s*\(resp\s*&&\s*resp\.success\)/.test(removalWindow);
    if (!ok) {
      g.fail('F4c-M08：字体保存/删除仍未判 success:false，失败会被念成「已应用 / 已删除」');
    } else {
      g.ok('F4c-M08：字体保存与删除都读回执，success:false 不再走成功提示');
    }
    addCase('F4c-M08', ok);
  }
}

// ---------- P0-F4a2-M31：防恢复 setPref 只传布尔，读取兼容历史布尔值 ----------
{
  const src = read('src/scripts/startup.js');
  if (!src) {
    g.fail('F4a2-M31：src/scripts/startup.js 不存在（判定对象缺失）');
  } else {
    const clean = blankNonCode(src, 'js', { keepStrings: true });
    const syncBlock = funcBlock(clean, 'syncDefendEnabledPref') || '';
    const persistBlock = funcBlock(clean, 'persistDefendPref') || '';
    const judge = (text) => {
      const sync = funcBlock(text, 'syncDefendEnabledPref') || '';
      const persist = funcBlock(text, 'persistDefendPref') || '';
      return /typeof\s+enabled\s*!==\s*'boolean'/.test(sync)
        && /setPref\(DEFEND_PREF_KEY,\s*enabled\)/.test(sync)
        && /resp\.success\s*!==\s*true/.test(sync)
        && /syncDefendEnabledPref\(defendStore\.enabled\s*===\s*true\)/.test(persist)
        && /typeof\s+v\s*===\s*'boolean'/.test(text);
    };
    const goodSample = [
      'function syncDefendEnabledPref(enabled) {',
      "  if (typeof enabled !== 'boolean') return false;",
      '  setPref(DEFEND_PREF_KEY, enabled);',
      '  if (resp.success !== true) return false;',
      '}',
      'function persistDefendPref() { syncDefendEnabledPref(defendStore.enabled === true); }',
      "if (typeof v === 'boolean') use(v);",
    ].join('\n');
    const badSample = [
      'function syncDefendEnabledPref(enabled) {',
      '  setPref(DEFEND_PREF_KEY, { enabled });',
      '}',
      'function persistDefendPref() { syncDefendEnabledPref({ enabled: true }); }',
      'if (v && typeof v === "object") use(v);',
    ].join('\n');
    if (!judge(goodSample) || judge(badSample)) {
      g.fail('F4a2-M31 正向对照失败：偏好布尔契约判定器失真（必须能把「布尔载荷+读回执」与「对象载荷+只 catch」分开）');
    }
    const ok = judge(clean) && /typeof\s+enabled\s*!==\s*'boolean'/.test(syncBlock)
      && /syncDefendEnabledPref\(defendStore\.enabled\s*===\s*true\)/.test(persistBlock);
    if (!ok) {
      g.fail('F4a2-M31：防恢复 setPref 仍传对象/未判 success，或读取端未兼容历史布尔值');
    } else {
      g.ok('F4a2-M31：防恢复只写布尔总开关并判回执，读取端兼容历史布尔值');
    }
    addCase('F4a2-M31', ok);
  }
}

// ---------- P2/C-W1+C-W2：A1-L01/L02 / A2-L01/L02 / F4a1-L15 / F4b-L02/L07 / F4b-M03 / F3-L15 / F4c-L17 ----------
{
  const appSrc = read('src/scripts/app.js') || '';
  const optSrc = read('src/scripts/optimizer.js') || '';
  const cleanSrc = read('src/scripts/cleanup.js') || '';
  const rtSrc = read('src/scripts/realtime.js') || '';
  const updSrc = read('src/scripts/updater-ui.js') || '';

  // A1-L01：保存失败与「不适用」分开，savedTo:null 必须清掉旧路径
  {
    const block = funcBlock(updSrc, 'fillModal') || '';
    const initBlock = windowAfter(updSrc, "savedTo: ''", 8) || '';
    const stateBlock = windowAfter(updSrc, "if (s && Object.prototype.hasOwnProperty.call(s, 'savedTo'))", 8) || '';
    const judge = (modal, init, state) => modal.includes('安装包保存失败：')
      && modal.includes('state.saveError')
      && init.includes("saveError: ''")
      && state.includes("s.savedTo || ''")
      && state.includes("s.saveError || ''");
    const goodModal = "const desc = savedTo ? '已存到' : state.saveError ? '安装包保存失败：' + state.saveError : '';";
    const goodInit = String.raw`savedTo: '',
    saveError: ''`;
    const goodState = "state.savedTo = s.savedTo || '';\nstate.saveError = s.saveError || '';";
    const badModal = "const desc = savedTo ? '已存到' : '';";
    if (!judge(goodModal, goodInit, goodState) || judge(badModal, goodInit, goodState)) {
      g.fail('A1-L01 正向对照失败：安装包保存失败态判定器失真');
    }
    const ok = judge(block, initBlock, stateBlock);
    if (!ok) g.fail('A1-L01：updater-ui.js 仍把 savedTo:null / saveError 当「不适用」，保存失败不会独立显示原因');
    else g.ok('A1-L01：安装包保存失败独立显示原因，null 不沿用旧路径');
    addCase('A1-L01', ok);
  }

  // A1-L02：unknown 只能显示「未知」，不能折成「不支持」
  {
    const block = funcBlock(appSrc, 'loadAppInfo') || '';
    const judge = (text) => /unknown:\s*'未知'/.test(text) && /none:\s*'不支持'/.test(text);
    const good = "const fluentText = { full: 'x', partial: 'y', none: '不支持', unknown: '未知' };";
    const bad = "const fluentText = { full: 'x', partial: 'y', none: '不支持' };";
    if (!judge(good) || judge(bad)) {
      g.fail('A1-L02 正向对照失败：fluent 档位判定器失真（必须能把 unknown=未知 与缺档分开）');
    }
    const ok = judge(block);
    if (!ok) g.fail('A1-L02：app.js 的 fluentText 未把 unknown 映射为「未知」 ⇒ 查询失败会被写成「不支持」');
    else g.ok('A1-L02：fluentSupport=unknown 显示「未知」，none 才显示「不支持」');
    addCase('A1-L02', ok);
  }

  // A2-L01：判据后立刻上锁/禁用按钮，再进 await
  {
    const clean = blankNonCode(optSrc, 'js');
    const orderOk = (name) => {
      const block = funcBlock(clean, name) || '';
      if (!block) return false;
      const lines = block.split('\n');
      const lockAt = lines.findIndex(l => l.includes('batchRunning = true;'));
      if (lockAt < 0) return false;
      const firstAwait = lines.findIndex((l, i) => i < lockAt && /\bawait\b/.test(l));
      const after = lines.slice(lockAt, lockAt + 4).join('\n');
      return firstAwait < 0 && /btn\.disabled\s*=\s*true/.test(after);
    };
    const good = 'async function runSelected() {\n  if (batchRunning) return;\n  batchRunning = true;\n  const btn = document.getElementById("x");\n  if (btn) btn.disabled = true;\n  try { await go(); } finally { batchRunning = false; }\n}';
    const bad = 'async function runSelected() {\n  if (batchRunning) return;\n  await choices();\n  batchRunning = true;\n  try { await go(); } finally { batchRunning = false; }\n}';
    const judge = (text) => {
      const lines = text.split('\n');
      const lockAt = lines.findIndex(l => l.includes('batchRunning = true;'));
      if (lockAt < 0) return false;
      const firstAwait = lines.findIndex((l, i) => i < lockAt && /\bawait\b/.test(l));
      return firstAwait < 0 && /btn\.disabled\s*=\s*true/.test(lines.slice(lockAt, lockAt + 4).join('\n'));
    };
    if (!judge(good) || judge(bad)) {
      g.fail('A2-L01 正向对照失败：批量上锁顺序判定器失真（必须能把「先上锁再 await」与「先 await 后上锁」分开）');
    }
    const ok = orderOk('runSelected') && orderOk('runBatch');
    if (!ok) g.fail('A2-L01：runSelected / runBatch 仍有 await 早于 batchRunning = true ⇒ 二连点会发两批');
    else g.ok('A2-L01：两处批量入口都在第一个 await 之前上锁并禁用按钮');
    addCase('A2-L01', ok);
  }

  // A2-L02：模块 init 失败必须进日志页
  {
    const block = funcBlock(appSrc, 'initModuleByName') || '';
    const judge = (text) => /catch\s*\(e\)\s*\{[\s\S]*console\.warn[\s\S]*window\.app\?\.log\?\.\(['"]error['"]/.test(text);
    const good = 'try { init(); } catch (e) { console.warn("x", e); window.app?.log?.("error", "模块 x 初始化失败"); }';
    const bad = 'try { init(); } catch (e) { console.warn("x", e); }';
    if (!judge(good) || judge(bad)) {
      g.fail('A2-L02 正向对照失败：模块 init 失败留痕判定器失真');
    }
    const ok = judge(block);
    if (!ok) g.fail('A2-L02：initModuleByName 仍只 console.warn，日志页看不到模块名与异常');
    else g.ok('A2-L02：模块 init 失败同时写 console 与日志页');
    addCase('A2-L02', ok);
  }

  // F4c-L17：手动检查 catch 也要构造 ok:false，并清 pendingManual
  {
    const block = funcBlock(updSrc, 'manualCheck') || '';
    const judge = (text) => /catch\s*\(e\)\s*\{[\s\S]*ok:\s*false[\s\S]*pendingManual\s*=\s*false/.test(text);
    const good = 'try { res = await check(); } catch (e) { res = { ok: false, error: e.message }; pendingManual = false; }';
    const bad = 'try { res = await check(); } catch (e) { res = { error: e.message }; }';
    if (!judge(good) || judge(bad)) {
      g.fail('F4c-L17 正向对照失败：手动检查兜底态判定器失真');
    }
    const ok = judge(block);
    if (!ok) g.fail('F4c-L17：手动检查 catch 未构造 ok:false / 未清 pendingManual，回流丢失时下一轮后台检查会被当手动弹窗');
    else g.ok('F4c-L17：手动检查兜底构造 ok:false 并清 pendingManual');
    addCase('F4c-L17', ok);
  }

  // F3-L17：子窗提示同文案不得叠一条，且旧定时器只清对应 token
  {
    const subToastSrc = read('src/scripts/sub-toast.js') || '';
      const factory = (text) => new Function('document', text + '; return { stack: stack, clear: clear };')({
        createElement: (tag) => ({
          tagName: tag,
          dataset: {},
          textContent: '',
          remove() { this.removed = true; },
        }),
      });
    const good = [
      "var token = 0; var timers = [];",
      "function stack(type, message, host) {",
      "  var found = host.children.find(function (child) { return child.dataset.trimSubToastMessage === message; });",
      "  var current = ++token;",
      "  if (found) { found.dataset.trimSubToastToken = String(current); return; }",
      "  var el = document.createElement('div'); el.dataset.trimSubToastMessage = message; el.dataset.trimSubToastToken = String(current); host.appendChild(el);",
      "}",
      // 旧定时器带着**旧 token** 来清：条目上的 token 已被新一轮改成更新的值 ⇒ 不得清掉。
      "function clear(el, current) { if (el.dataset.trimSubToastToken === String(current)) el.remove(); }",
    ].join('\n');
    const bad = [
      // 反样本：按**内容相等**判定（不看 token）⇒ 同文案重复写入叠成两条，
      // 且旧定时器会把新一轮同文案的条目一起清掉。
      "function stack(type, message, host) { var el = document.createElement('div'); el.dataset.message = message; el.textContent = message; host.appendChild(el); }",
      "function clear(el, current) { if (el.textContent === el.dataset.message) el.remove(); }",
    ].join('\n');
    let ok = false;
    try {
      const goodEnv = factory(good);
      const badEnv = factory(bad);
      const makeHost = () => ({ children: [], appendChild(child) { this.children.push(child); } });
      const run = (env) => {
        const host = makeHost();
        env.stack('error', 'same', host);
        env.stack('error', 'same', host);
        const first = host.children[0];
        const stale = first.dataset.trimSubToastToken === '2';
        // 旧定时器带的是第一轮的 token（1），而条目已被第二轮刷新成 2 ⇒ 旧定时器不得清它。
        env.clear(first, 1);
        return { count: host.children.length, stale, removed: first.removed === true };
      };
      const goodResult = run(goodEnv);
      const badResult = run(badEnv);
      ok = goodResult.count === 1 && goodResult.stale === true && goodResult.removed === false
        && badResult.count === 2 && badResult.stale === false && badResult.removed === true;
    } catch (e) {}
    if (!ok) g.fail('F3-L17 正向对照失败：子窗提示 token 判定器失真');
    const live = subToastSrc.includes('trimSubToastToken') && subToastSrc.includes('trimSubToastMessage') && subToastSrc.includes('setTimeout');
    if (!live) g.fail('F3-L17：sub-toast.js 未按文案/token 判定，同文案重复写入仍会叠条或旧定时器误清新条');
    if (ok && live) g.ok('F3-L17：同文案提示按 token 收口，旧定时器只清对应条目');
    addCase('F3-L17', ok && live);
  }

  // A2-L05：tick / tickLoss 必须有 catch；sampleOnce 的渲染段也在 try 内
  {
    const tick = funcBlock(rtSrc, 'tick') || '';
    const tickLoss = funcBlock(rtSrc, 'tickLoss') || '';
    const sample = funcBlock(rtSrc, 'sampleOnce') || '';
    const judge = (t, tl, s) => /await sampleOnce\(\)[\s\S]*catch\s*\(e\)/.test(t)
      && /await lossOnce\(\)[\s\S]*catch\s*\(e\)/.test(tl)
      && /state\.up = up;[\s\S]*try\s*\{[\s\S]*pushPoint\(up, down\)/.test(s);
    const goodT = 'try { await sampleOnce(); } catch (e) { log(e); } finally { busy = false; }';
    const goodTL = 'try { await lossOnce(); } catch (e) { log(e); } finally { busy = false; }';
    const goodS = 'state.up = up; try { pushPoint(up, down); renderMetrics(); draw(); } catch (e) { log(e); }';
    const badT = 'try { await sampleOnce(); } finally { busy = false; }';
    if (!judge(goodT, goodTL, goodS) || judge(badT, goodTL, goodS)) {
      g.fail('A2-L05 正向对照失败：实时轮询 catch 判定器失真');
    }
    const ok = judge(tick, tickLoss, sample);
    if (!ok) g.fail('A2-L05：tick/tickLoss 缺 catch，或 pushPoint/renderMetrics/draw 仍在 try 外');
    else g.ok('A2-L05：tick/tickLoss 有 catch，采样渲染段纳入 try');
    addCase('A2-L05', ok);
  }

  // F4a1-L15：逐条还原必须单条 try/catch 且累计 restored/skipped/failed
  {
    const clean = blankNonCode(cleanSrc, 'js', { keepStrings: true });
    const win = windowAfter(clean, 'for (let i = 0; i < m.count; i++)', 50) || '';
    const judge = (text) => /try\s*\{[\s\S]*fileBackupRestore[\s\S]*\}\s*catch[\s\S]*failed\+\+[\s\S]*continue;/.test(text)
      && /restored\+\+/.test(text) && /skipped\+\+/.test(text) && /失败 \$\{failed\}/.test(text);
    const good = 'for (let i = 0; i < m.count; i++) {\n  try { r = await api.fileBackupRestore(m.file, i); } catch (e) { failed++; failedItems.push(e); continue; }\n  if (r.restored) restored++; else skipped++;\n}\ntoast(`恢复 ${restored}，跳过 ${skipped}，失败 ${failed}`);';
    const bad = 'for (let i = 0; i < m.count; i++) {\n  const r = await api.restore(i);\n  if (r.restored) restored++; else skipped++;\n}';
    if (!judge(good) || judge(bad)) {
      g.fail('F4a1-L15 正向对照失败：逐条还原判定器失真（必须能把「单条 catch + 三计数」与「整批单 try」分开）');
    }
    const ok = judge(win);
    if (!ok) g.fail('F4a1-L15：文件备份还原循环仍是整批单 try 或未累计 failed ⇒ 单条 reject 会中断整批');
    else g.ok('F4a1-L15：文件备份逐条还原，单条失败不中断并累计 restored/skipped/failed');
    addCase('F4a1-L15', ok);
  }

  // F4b-L02：全被预检拦下时不得再弹「只执行剩下的零项」
  {
    const block = funcBlock(blankNonCode(optSrc, 'js', { keepStrings: true }), 'filterByPreflight') || '';
    const judge = (text) => {
      const guard = text.indexOf('if (!kept.length)');
      const confirm = text.indexOf('window.app.confirm');
      return guard >= 0 && confirm > guard && text.includes('return [];');
    };
    const good = 'async function filterByPreflight(batch) {\n  const kept = [];\n  if (!kept.length) { toast("全部优化项被预检拦截"); return []; }\n  const go = await window.app.confirm("x");\n}';
    const bad = 'async function filterByPreflight(batch) {\n  const kept = [];\n  const go = await window.app.confirm("只执行剩下的 " + kept.length + " 项");\n}';
    if (!judge(good) || judge(bad)) {
      g.fail('F4b-L02 正向对照失败：全拦短路判定器失真');
    }
    const ok = judge(block);
    if (!ok) g.fail('F4b-L02：kept.length===0 仍走确认框或没有列出拦截原因');
    else g.ok('F4b-L02：全部被预检拦截时直接提示原因，不再弹「只执行剩下的零项」');
    addCase('F4b-L02', ok);
  }

  // F4b-L07：悬浮索引必须按绘图区换算
  {
    const block = funcBlock(rtSrc, 'hoverIndexAt') || '';
    const evalFn = (text) => {
      try {
        return new Function('CHART_PAD_L', 'CHART_PAD_R', 'return (' + text + ');')(56, 12);
      } catch (e) { return null; }
    };
    const judge = (fn) => !!fn
      && fn(56, 400, 10) === 0
      && fn(388, 400, 10) === 9
      && fn(0, 400, 10) === 0
      && fn(400, 400, 10) === 9;
    const good = 'function hoverIndexAt(x, chartWidth, count) { const plotW = chartWidth - CHART_PAD_L - CHART_PAD_R; if (!(count > 0) || !(plotW > 0)) return 0; const idx = Math.round(((x - CHART_PAD_L) / plotW) * (count - 1)); return Math.max(0, Math.min(count - 1, idx)); }';
    const bad = 'function hoverIndexAt(x, chartWidth, count) { return Math.max(0, Math.min(count - 1, Math.round((x / chartWidth) * (count - 1)))); }';
    if (!judge(evalFn(good)) || judge(evalFn(bad))) {
      g.fail('F4b-L07 正向对照失败：绘图区映射判定器失真（整幅宽映射必须被识破）');
    }
    const ok = judge(evalFn(block));
    if (!ok) g.fail('F4b-L07：hoverIndexAt 未按绘图区（扣左右 padding）换算或端点未 clamp');
    else g.ok('F4b-L07：悬浮索引按绘图区换算，左右端点 clamp 到首尾采样点');
    addCase('F4b-L07', ok);
  }

  // F4b-M03：两处「执行所选」入口必须套 guardAsync
  {
    const block = funcBlock(blankNonCode(optSrc, 'js', { keepStrings: true }), 'bindEvents') || '';
    const judge = (text) => text.includes('const guardBatch = (label, fn) => guardAsync(')
      && text.includes("guardBatch('批量执行', runBatch)")
      && text.includes("guardBatch('执行所选', runSelected)");
    const good = "const guardBatch = (label, fn) => guardAsync(label, () => fn());\nbatchBtn.addEventListener('click', guardBatch('批量执行', runBatch));\nselectedBtn.addEventListener('click', guardBatch('执行所选', runSelected));";
    const bad = "batchBtn.addEventListener('click', () => runBatch());\nselectedBtn.addEventListener('click', () => runSelected());";
    if (!judge(good) || judge(bad)) {
      g.fail('F4b-M03 正向对照失败：批量入口 guardAsync 判定器失真');
    }
    const ok = judge(block);
    if (!ok) g.fail('F4b-M03：runSelected / runBatch 入口未套 guardAsync ⇒ 确认链 reject 仍是浮动 Promise');
    else g.ok('F4b-M03：两处「执行所选」入口都经 guardAsync 收口');
    addCase('F4b-M03', ok);
  }

  // F3-L15：进度 Toast pinned，普通提示 FIFO 不得挤掉
  {
    const toastBlock = funcBlock(appSrc, 'toast') || '';
    const trimBlock = funcBlock(appSrc, 'trimToasts') || '';
    const createBlock = funcBlock(optSrc, 'createProgressToast') || '';
    const finishBlock = funcBlock(optSrc, 'finishProgressToast') || '';
    const judge = (toastText, trimText, createText, finishText) => /pinned:\s*options\.pinned === true/.test(toastText)
      && /!\s*t\.pinned/.test(trimText)
      && /pinned:\s*true/.test(createText)
      && /t\.pinned\s*=\s*false/.test(finishText);
    const goodToast = 'const entry = { el, pinned: options.pinned === true };';
    const goodTrim = 'const idx = activeToasts.findIndex((t) => t && t.el && !t.pinned);';
    const goodCreate = 'const entry = { el, pinned: true };';
    const goodFinish = 't.pinned = false;';
    const badToast = 'const entry = { el };';
    const badTrim = 'const idx = activeToasts.findIndex((t) => t && t.el);';
    if (!judge(goodToast, goodTrim, goodCreate, goodFinish) || judge(badToast, badTrim, goodCreate, goodFinish)) {
      g.fail('F3-L15 正向对照失败：pinned Toast 判定器失真');
    }
    const ok = judge(toastBlock, trimBlock, createBlock, finishBlock);
    if (!ok) g.fail('F3-L15：进度 Toast 未 pinned 或 trimToasts 未跳过 pinned ⇒ 普通提示会挤掉进度条');
    else g.ok('F3-L15：进度 Toast pinned，FIFO 跳过 pinned，完成后显式 unpin');
    addCase('F3-L15', ok);
  }

  // F4a1-L17：卸载页每次进入重新枚举
  {
    const unSrc = read('src/scripts/uninstall.js') || '';
    const switchBlock = funcBlock(blankNonCode(appSrc, 'js', { keepStrings: true }), 'switchPageInner') || '';
    const judge = (sw, un) => /pageName === 'uninstall'/.test(sw)
      && /window\.uninstall\?\.refresh\?\.\(\)/.test(sw)
      && /window\.uninstall = \{ init, refresh: loadApps \}/.test(un);
    const goodSw = "if (pageName === 'uninstall') await window.uninstall?.refresh?.();";
    const goodUn = 'window.uninstall = { init, refresh: loadApps };';
    const badSw = "if (pageName === 'uninstall') initModuleByName('uninstall');";
    const badUn = 'window.uninstall = { init };';
    if (!judge(goodSw, goodUn) || judge(badSw, badUn)) {
      g.fail('F4a1-L17 正向对照失败：卸载页进页钩子判定器失真');
    }
    const ok = judge(switchBlock, unSrc);
    if (!ok) g.fail('F4a1-L17：switchPage 未在每次进入卸载页时调用 refresh ⇒ 第二次进入仍是首次缓存');
    else g.ok('F4a1-L17：卸载页每次进入调用 window.uninstall.refresh() 重新枚举');
    addCase('F4a1-L17', ok);
  }

  // F4a1-L18：文件清理成功后三份数据同步收缩
  {
    const block = funcBlock(cleanSrc, 'syncFileCleanAfterExecute') || '';
    const judge = (text) => /fileCleanData\.delete\(id\)/.test(text)
      && /scanResults\.delete\(id\)/.test(text)
      && /selectedIds\.delete\(id\)/.test(text)
      && /okPaths/.test(text);
    const good = 'function syncFileCleanAfterExecute(id, data, details) { const okPaths = new Set(); fileCleanData.delete(id); scanResults.delete(id); selectedIds.delete(id); }';
    const bad = 'function syncFileCleanAfterExecute(id, data, details) { scanResults.delete(id); }';
    if (!judge(good) || judge(bad)) {
      g.fail('F4a1-L18 正向对照失败：文件清理三份数据收缩判定器失真');
    }
    const ok = judge(block);
    if (!ok) g.fail('F4a1-L18：文件清理成功后未同步删 fileCleanData/scanResults/selectedIds ⇒ 预览仍指向已删图片');
    else g.ok('F4a1-L18：文件清理成功后按逐文件 status 收缩三份数据');
    addCase('F4a1-L18', ok);
  }

  // F4b-M02：svcAppliedGb 只在执行成功后写
  {
    const block = windowAfter(blankNonCode(optSrc, 'js', { keepStrings: true }),
      'const ok = await runOptionActive(dynP, opt)', 5) || '';
    const judge = (text) => /const ok = await runOptionActive\(dynP, opt\)/.test(text)
      && /if \(ok && opt\.id === 'svc_mem_gb'\) svcAppliedGb = normalizeSvcTier\(dynP\.gb\)/.test(text);
    const good = "const ok = await runOptionActive(dynP, opt);\nif (ok && opt.id === 'svc_mem_gb') svcAppliedGb = normalizeSvcTier(dynP.gb);";
    const bad = "if (opt.id === 'svc_mem_gb') svcAppliedGb = normalizeSvcTier(dynP.gb);\nawait runOptionActive(dynP, opt);";
    if (!judge(good) || judge(bad)) {
      g.fail('F4b-M02 正向对照失败：svcAppliedGb 成功后才写判定器失真');
    }
    const ok = judge(block);
    if (!ok) g.fail('F4b-M02：svcAppliedGb 仍在执行前写入 ⇒ 失败后按钮显示「已应用」无法重试');
    else g.ok('F4b-M02：svcAppliedGb 只在 runOptionActive 成功后写入');
    addCase('F4b-M02', ok);
  }
}

if (!g.skipUnlessPresent(join(ROOT, 'src', 'scripts', 'optimizer.js'), 'src/scripts（本门禁的判定对象）')) g.finish();

const failed = CASES.filter(c => !c.ok).length;
if (failed > 0) g.fail(`回执三态判据：${failed} 条不达标（共 ${CASES.length} 条）`);
else g.ok(`回执三态判据：${CASES.length} 条全部达标`);

g.finish('check-receipt-tri-state: 全部通过');
