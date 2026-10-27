'use strict';
// tools/check-pending-receipt-fields.mjs —— 回执字段 ⇄ 前端消费（X0-6 S1/S3、NC-01 的机检形态）
//
// 出处：2026-10-26 复审 X0-6 建形扫描（同一回执、两个消费者分叉）与 2026-10-28 P3 施工。
// 三类病根，分别是：
//   S1  待删台账回执带恒真 `pfroReadable`、`batchId`/`addedAt` 无消费，按批撤回无调用方；
//   S3  占用查询卡片不读 `malformed/partial`，协议被打断时照常显示「没有发现占用」；
//   NC  netcheck 前端读物理网卡七字段，而后端 `nicProps.physical` 恒为空数组。
//
// 判据只看源码形态（本仓前端没有 JS 单测装置），与 check-receipt-tri-state 同款做法。
// 每条判据都带一个正向对照样本：判据必须能对坏样本判红，否则这里的绿是空绿。
//
// 用法：node tools/check-pending-receipt-fields.mjs

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { gate } from './lib/gate.mjs';

const ROOT = process.cwd();
const g = gate(import.meta.url);

const read = (rel) => {
  const abs = join(ROOT, rel);
  return existsSync(abs) ? readFileSync(abs, 'utf8') : null;
};

/** 截取 `fn` 起点到下一个顶层 `}` 的粗块（只用于本文件的同形判断）。 */
function fnBlock(src, sig) {
  const i = src.indexOf(sig);
  if (i < 0) return '';
  const j = src.indexOf('\n}', i);
  return j < 0 ? src.slice(i) : src.slice(i, j + 2);
}

// —— 判据（纯函数，便于正向对照） ——
const pendingRowHasAddedAt = (s) => /"addedAt"\s*:\s*e\["addedAt"\]/.test(s);
const hasPfroReadable = (s) => s.includes('pfroReadable');
const revokeTakesBatch = (s) => fnBlock(s, 'pub async fn uninstall_pending_revoke').includes('batch_id');
const apiRevokeTakesArg = (s) => /pendingRevoke:\s*function\s*\(\s*[A-Za-z]/.test(s);
const cleanupShowsAddedAt = (s) => s.includes('fmtPendingAddedAt(e.addedAt)');
const lockQueryReadsMalformed = (s) => /function renderLockQueryResult[\s\S]*?resp\.malformed/.test(s);
const netcheckReadsPhysical = (s) => /\ba\.(kind|status|speed|rss|csum|pmOff|wolMagic|props)\b/.test(s);

const pending = read('src-tauri/src/commands/uninstall/pending_delete.rs');
const cleanup = read('src/scripts/cleanup.js');
const netcheck = read('src/scripts/netcheck.js');
const api = read('src/scripts/tauri-api.js');

if (!pending || !cleanup || !netcheck || !api) {
  g.fail('缺少目标文件（本门禁不 SKIP：这四处都是跟踪文件）');
  g.finish();
} else {
  // ① X0-6 S1：台账回执
  if (!pendingRowHasAddedAt(pending)) g.fail('待删清单行必须带 addedAt（UI 要显示登记时间）');
  if (hasPfroReadable(pending)) g.fail('禁用/删除恒真装饰字段 pfroReadable');
  if (revokeTakesBatch(pending)) g.fail('uninstall_pending_revoke 不得保留无调用方的 batch_id 参数');
  if (apiRevokeTakesArg(api)) g.fail('tauri-api 的 pendingRevoke 不得再暴露 batchId 形参');
  if (!cleanupShowsAddedAt(cleanup)) g.fail('待删清单弹窗必须消费 addedAt（登记时间）');

  // ② X0-6 S3：同一回执的第二个消费方
  if (!lockQueryReadsMalformed(cleanup)) {
    g.fail('renderLockQueryResult 必须消费 resp.malformed（畸形行数）');
  }

  // ③ NC-01：后端永不为空的 physical 不得留前端读取面
  if (netcheckReadsPhysical(netcheck)) {
    g.fail('netcheck 不得再读物理网卡七字段（后端 physical 恒为空数组）');
  }
  if (!netcheck.includes('renderNicProps')) g.fail('虚拟网卡只读区不得整体消失');

  // 正向对照：判据必须能把坏样本判红
  const controls = [
    [!pendingRowHasAddedAt('"batchId": e["batchId"],'), '缺少 addedAt 的样本未被识别'],
    [hasPfroReadable('"pfroReadable": true,'), 'pfroReadable 样本未被识别'],
    [revokeTakesBatch('pub async fn uninstall_pending_revoke<R: tauri::Runtime>(window: WebviewWindow<R>, batch_id: Option<String>) -> Value {'), 'batch_id 形参未被识别'],
    [apiRevokeTakesArg('pendingRevoke: function (batchId) {'), 'pendingRevoke 形参未被识别'],
    [!cleanupShowsAddedAt('const label = base;'), '未消费 addedAt 的样本未被识别'],
    [!lockQueryReadsMalformed('function renderLockQueryResult(resp) { const procs = []; }'), '不读 malformed 的样本未被识别'],
    [netcheckReadsPhysical('if (a.rss === true) st.push(1);'), '物理七字段读取样本未被识别'],
  ];
  const broken = controls.filter(([pass]) => !pass);
  if (broken.length === 0) {
    g.ok(`判据在位（${controls.length} 条正向对照全红）`);
  } else {
    g.fail(`正向对照失效（判据必须能判红）：${broken.map(([, msg]) => msg).join('；')}`);
  }
}

g.finish('check-pending-receipt-fields: 全部通过');
