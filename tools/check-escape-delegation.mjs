// check-escape-delegation.mjs —— 本地 escape* 薄包装「只许委托、不许重实现/新增」门禁
// （审查 L3 2026-10-01 NEW-3）
//
// 背景：转义唯一真源是 ds.js（ds.esc / ds.escAttr；escAttr 与 esc 同字符集，因
// 「哪个引号包属性」会随改动变——见 AGENTS.md 硬性红线）。历史上各脚本留下本地
// escapeHtml/escapeAttr 薄包装，红线口径为「历史存量不扩散」。真实危害是**重实现**
// （字符集与 ds 不一致 → 转义口径分叉、单引号漏 escaping 导致属性逃逸），而非委托
// 本身。故本门禁断言两件事：
//   1) 每一个本地 escapeHtml/escapeAttr 定义体必须是纯委托
//      `return window.ds.esc(...)` / `return window.ds.escAttr(...)`（含薄计算亦可，
//      但必须以 window.ds.esc/escAttr 的返回值为最终返回）；
//   2) 定义总数不得超过 BASELINE（29，2026-10-01 现盘实测）——只许随收敛递减，
//      新文件/新代码再定义即红（棘轮）。
// 完全收敛（删包装、调用点直用 window.ds.*）为渐进目标：触到哪个文件顺手改哪个，
// 改完把 BASELINE 相应下调即可（下调无需审批，上调即红）。
//
// 判红验证：① 把任一包装体改成非委托实现（如 `return s;`）→ 红；
//           ② 任一文件临时加 `function escapeHtml(s) { return s; }` → 红（计数+形态双红）。
//
// 用法：node tools/check-escape-delegation.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

// 基线 = 2026-10-01 L3 审查时现盘定义数（24 文件 29 个，全为纯委托）。只许下调。
const BASELINE = 29;

const dir = join(REPO_ROOT, 'src', 'scripts');
const files = readdirSync(dir).filter((f) => f.endsWith('.js')).sort();

function stripBlockComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
}

// 定义体允许跨行；体内容不含 `}` 的前提下整段截取（包装函数极薄，足够）
const RE_DEF = /function\s+(escapeHtml|escapeAttr)\s*\([^)]*\)\s*\{([^}]*)\}/g;

let fail = 0;
let count = 0;
const badForm = [];

for (const f of files) {
  const text = stripBlockComments(readFileSync(join(dir, f), 'utf8'));
  let m;
  RE_DEF.lastIndex = 0;
  while ((m = RE_DEF.exec(text)) !== null) {
    count++;
    const kind = m[1];
    const body = m[2].trim();
    const fn = kind === 'escapeHtml' ? 'esc' : 'escAttr';
    // 纯委托判定：返回值必须来自 window.ds.esc / window.ds.escAttr
    if (!new RegExp(`return\\s+window\\.ds\\.${fn}\\s*\\(`).test(body)) {
      const line = text.slice(0, m.index).split('\n').length;
      badForm.push(`${f}:${line} ${kind}`);
    }
  }
}

console.log('=== 本地 escape* 薄包装委托与棘轮门禁 ===\n');
for (const b of badForm) {
  console.error(`✗ ${b} — 定义体不是 window.ds.esc/escAttr 纯委托（重实现会与真源字符集分叉）`);
  fail++;
}
const okCount = count <= BASELINE;
console.log(`${okCount ? '✓' : '✗'} 定义总数 ${count} ${okCount ? '≤' : '>'} 基线 ${BASELINE}（只许递减，禁止新增）`);
if (!okCount) fail++;

console.log('');
if (fail > 0) {
  console.error('门禁失败：本地 escape* 包装违反委托/棘轮约束（见上）');
  process.exit(1);
}
console.log(`本地 escape* 包装门禁通过（${count}/${BASELINE}）`);
