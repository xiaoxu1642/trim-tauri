// check-finder-scan-notes.mjs —— 扫描回执的提示条目门禁（P1-04）
//
// 为什么要有这条：finder 的扫描回执里带着「条目截断 / 读不到的目录 / 丢根 / 根数超限」
// 四个判据，前端要把它们翻成给用户看的话。改前端时最容易出的错是**字段名读错**
// （把 rootsTruncated 读成 truncated、把 droppedRoots 读成 errors）——
// 这种错不会报错，只会让提示少一条或多一条，用户看到的仍是「扫描完成」。
//
// 本门禁**不复制实现**：把 src/scripts/finder.js 里的 finderScanNotes 切出来直接跑，
// 复制出来的副本会和线上代码漂移，那比没有门禁更坏（同 tools/check-treemap-layout.mjs）。
//
// 判据：
//   ① 真实回执形 {success:true,data:[],droppedRoots:2,rootsTruncated:true} ⇒ 两条提示；
//   ② {success:true,data:[],droppedRoots:0,rootsTruncated:false} ⇒ 无额外提示；
//   ③ 字段名必须读对（把 rootsTruncated 换成 truncated ⇒ ① 必红）；
//   ④ 提示文案要点名数量（用户得知道丢了几个目录）；
//   ⑤ 调用点必须真的用这份函数（不许留一份没人调用的实现）。
//
// 用法：node tools/check-finder-scan-notes.mjs
import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { REPO_ROOT } from './ps-origin.mjs';

const JS = join(REPO_ROOT, 'src', 'scripts', 'finder.js');
const src = readFileSync(JS, 'utf8');
const start = src.indexOf('function finderScanNotes');
const end = src.indexOf('function render(key)');
if (start < 0 || end < 0 || end <= start) {
  console.log(`✗ 在 ${relative(REPO_ROOT, JS).replace(/\\/g, '/')} 里找不到 finderScanNotes / render(key) 边界`);
  console.log('  ⇒ 提示函数被改名或合并意味着这条门禁失去对照物，必须同步改本文件');
  process.exit(1);
}
const finderScanNotes = new Function(`${src.slice(start, end)}; return finderScanNotes;`)();

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};
console.log('=== finder 扫描提示条目门禁 ===\n');

// ① 真实回执形：丢根 + 根截断 ⇒ 两条提示
const real = finderScanNotes({ success: true, data: [], droppedRoots: 2, rootsTruncated: true });
check(real.length === 2, '真实回执对照：丢根 2 个 + 根截断 ⇒ 两条提示', `实得 ${real.length} 条：${JSON.stringify(real)}`);

// ② 全零回执 ⇒ 无额外提示
const none = finderScanNotes({ success: true, data: [], droppedRoots: 0, rootsTruncated: false });
check(none.length === 0, '零值对照：丢根 0 + 未截断 ⇒ 无额外提示', `实得 ${none.length} 条：${JSON.stringify(none)}`);

// ③ 字段名读错必红：把 rootsTruncated 换成 truncated（条目截断）时，文案必须对不上
// —— 条数可能一样，但说的是两件事（「条目超上限」≠「目录数超上限」）
const wrongField = finderScanNotes({ success: true, data: [], droppedRoots: 2, truncated: true });
check(
  wrongField.join('|') !== real.join('|'),
  '字段名对照：根截断与条目截断是两个字段（读错必红）',
  `读错字段得 ${JSON.stringify(wrongField)}`,
);

// ④ 文案要点名数量
check(
  real.some((n) => n.includes('2')),
  '提示文案点名丢根数量',
  JSON.stringify(real),
);

// ⑤ 既有判据不被丢掉（条目截断 / 读不到的目录）
const legacy = finderScanNotes({ success: true, data: [], errors: 3, truncated: true });
check(legacy.length === 2, '条目截断 + 3 处无法读取 ⇒ 两条提示', `实得 ${legacy.length} 条`);

// ⑥ 调用点真的用这份函数（不许留一份没人调用的实现）
check(
  /finderScanNotes\(resp\)/.test(src),
  '扫描调用点使用 finderScanNotes（实现不许悬空）',
);

console.log('');
if (fail > 0) {
  console.log(`check-finder-scan-notes: ${fail} 条不通过`);
  process.exit(1);
}
console.log('check-finder-scan-notes: 全部通过');
