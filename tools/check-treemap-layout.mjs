// Treemap 布局门禁（M6 / Q4，2026-09-29）
//
// 为什么要有这条：分析器的 Treemap 是**纯数学**（squarified 布局），而本项目不用 CDP、
// 不许擅自起前台窗口 ⇒ 渲染观感只能人工目检，但布局的硬性质可以静默验：
//   ① 铺满容器（面积和 = 100%，缺角意味着后端占比算错）
//   ② 不越界（越界的格子被容器 overflow 裁掉，用户看到"目录比实际小"）
//   ③ 不重叠（重叠 = 点 A 格跳到 B，是最坏的一种"看着正常"）
//   ④ 格子面积占比 = 体积占比（面积不如实反映占比，Treemap 就没有存在意义）
//   ⑤ 项数守恒 + 退化输入不崩（空输入 0 格、0 体积项不占格）
// 本仓有假绿前科（v1 M13 / v2-M16），所以每条都取「破坏一次必红」的写法：
// 把竖条/横条两个分支的轴向写反（今天真错过一次），②③ 必红。
//
// 布局函数从 src/scripts/finder.js 里按函数名切出来跑，不复制第二份实现——
// 复制出来的副本会和线上代码漂移，那比没有门禁更坏。
import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { REPO_ROOT } from './ps-origin.mjs';

const JS = join(REPO_ROOT, 'src', 'scripts', 'finder.js');
const src = readFileSync(JS, 'utf8');
const start = src.indexOf('function anTreemapLayout');
const end = src.indexOf('function renderAnTreemap');
if (start < 0 || end < 0 || end <= start) {
  console.log(`✗ 在 ${relative(REPO_ROOT, JS).replace(/\\/g, '/')} 里找不到 anTreemapLayout / renderAnTreemap 边界`);
  console.log('  ⇒ 布局函数被改名或合并意味着这条门禁失去对照物，必须同步改本文件');
  process.exit(1);
}
const layout = new Function(`${src.slice(start, end)}; return anTreemapLayout;`)();

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};
console.log('=== Treemap 布局门禁 ===\n');

const EPS = 1e-6;
const sizes = [500, 300, 120, 80, 40, 20, 7, 3, 1, 1];
const items = sizes.map((v, i) => ({ size: v, path: `C:/x${i}` }));
const boxes = [[100, 46], [100, 10], [10, 200], [1000, 300], [3, 3]];

let allInside = true, allNoOverlap = true, allFill = true, allProportional = true, allCount = true;
let worstAspect = 0;
for (const [w, h] of boxes) {
  const cells = layout(items, w, h);
  if (cells.length !== items.length) allCount = false;
  let area = 0;
  for (const c of cells) {
    area += c.w * c.h;
    if (c.x < -EPS || c.y < -EPS || c.x + c.w > w + 1e-6 || c.y + c.h > h + 1e-6) allInside = false;
    worstAspect = Math.max(worstAspect, Math.max(c.w / c.h, c.h / c.w));
  }
  for (let i = 0; i < cells.length; i++) {
    for (let j = i + 1; j < cells.length; j++) {
      const a = cells[i], b = cells[j];
      const ix = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
      const iy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
      if (ix > 1e-6 && iy > 1e-6) allNoOverlap = false;
    }
  }
  if (Math.abs((area / (w * h)) * 100 - 100) > 0.5) allFill = false;
  const total = sizes.reduce((a, b) => a + b, 0);
  for (let i = 0; i < cells.length; i++) {
    const share = (cells[i].w * cells[i].h) / (w * h);
    if (Math.abs(share - sizes[i] / total) > 0.01) allProportional = false;
  }
}

check(allCount, '项数守恒：每个非零体积项都拿到一个格子');
check(allInside, '格子不越出容器（越界会被 overflow 裁成"目录变小"）');
check(allNoOverlap, '格子互不重叠（重叠 = 点 A 跳到 B）');
check(allFill, '铺满容器：面积和 = 100%（±0.5%）');
check(allProportional, '面积占比 = 体积占比（±1%）');

// 退化输入：空 / 全 0 / 单项 / 非正尺寸
const empty = layout([], 100, 46);
const zeros = layout([{ size: 0, path: 'a' }, { size: 5, path: 'b' }], 100, 46);
const single = layout([{ size: 9, path: 's' }], 100, 46);
const badBox = layout(items, 0, 46);
check(
  empty.length === 0 && zeros.length === 1 && Number(zeros[0].item.size) === 5
    && single.length === 1 && single[0].w === 100 && single[0].h === 46 && badBox.length === 0,
  '退化输入：空/全 0/单项/零尺寸容器都不崩且不占位',
  `空=${empty.length} 含零=${zeros.length} 单项=${single.length} 零容器=${badBox.length}`,
);

// 长宽比是 squarified 的目的本身；阈值放宽到 12 —— 极端扁容器（3x3、100x10）
// 下再好的算法也会出现细长格，这里钉的是"别退化成一条一条的切片图"
check(worstAspect < 12, '最坏长宽比 < 12（squarified 存在的理由就是不产出细面条格）', `实测 ${worstAspect.toFixed(2)}`);

console.log('');
if (fail > 0) {
  console.log(`Treemap 布局门禁 ${fail} 项未通过`);
  process.exit(1);
}
console.log('Treemap 布局门禁全部通过');
