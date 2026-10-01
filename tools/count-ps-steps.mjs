// count-ps-steps.mjs —— 数据层 pwsh 步骤计数（v2-R2：正向/恢复**分账**，不再有单一总数）
//
// 为什么必须分账：v1 方案只按 `steps[]` 统计出 48 个 pwsh 步，据此写「真正还需要
// PowerShell 的只剩 6 项 / 7 步」。而 `restore[]`（还原方向）另有 10 个 pwsh 步完全没被
// 计入 —— 于是「还剩多少 PS」这个决定退役排期的数字被系统性低估。
// 两个方向走的是同一条编译链（`pssteps::compile`），但**用户的还原动作**是否也去 PS 化，
// 是另一件事，所以必须分开看。
//
// 口径纪律：AGENTS.md / readme / 方案文档引用这里的任何数字，都必须现跑本工具，
// 不许把下面的数字抄进文档（v2 V2-06：手写数字必然漂移，本次漂移的就是「44」）。
//
// 用法：node tools/count-ps-steps.mjs

import { readFileSync } from 'node:fs';

const d = JSON.parse(readFileSync('src-tauri/data/optimizer-runtime.json', 'utf8'));

let items = 0;
let applyItems = 0, applySteps = 0;
let restoreItems = 0, restoreSteps = 0;
for (const o of d) {
  items++;
  const steps = o.steps || [];
  const restore = o.restore || [];
  const a = steps.filter((s) => s.pwsh).length;
  const r = restore.filter((s) => s.pwsh).length;
  if (a > 0) applyItems++;
  if (r > 0) restoreItems++;
  applySteps += a;
  restoreSteps += r;
}

console.log(`优化项总数（optimizer-runtime.json 顶层数组）: ${items}`);
console.log(`正向 steps[]：含 pwsh 的项 ${applyItems} / pwsh 步 ${applySteps}`);
console.log(`恢复 restore[]：含 pwsh 的项 ${restoreItems} / pwsh 步 ${restoreSteps}`);
console.log(`合计 pwsh 步: ${applySteps + restoreSteps}（= 正向 ${applySteps} + 恢复 ${restoreSteps}，两者不得互相代表）`);
console.log('');
console.log('注：以上是**数据层**账。命令层直调（optimizer.rs 的 run_inline_ps、uninstall.rs 的 Appx）');
console.log('    不在这里，由 node tools/check-ps-callsites.mjs 现算打印；原生/inbox 执行情况由');
console.log('    cargo test data_layer_coverage_report -- --nocapture 给出。');
