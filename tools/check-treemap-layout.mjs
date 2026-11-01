// Treemap 布局门禁（M6 / Q4，2026-09-29）
//
// 为什么要有这条：分析器的 Treemap 是**纯数学**（squarified 布局），而本项目不用 CDP、
// 不许擅自起前台窗口 ⇒ 渲染观感只能人工目检，但布局的硬性质可以静默验：
//   ① 铺满容器（缺角意味着后端占比算错）
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
const PAGES_CSS = join(REPO_ROOT, 'src', 'styles', 'main-pages.css');
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
function judgeCells(cells, w, h, sizes) {
  let inside = true, noOverlap = true, fill = true, proportional = true;
  let worstAspect = 0, area = 0;
  for (const c of cells) {
    area += c.w * c.h;
    if (c.x < -EPS || c.y < -EPS || c.x + c.w > w + 1e-6 || c.y + c.h > h + 1e-6) inside = false;
    worstAspect = Math.max(worstAspect, Math.max(c.w / c.h, c.h / c.w));
  }
  for (let i = 0; i < cells.length; i++) {
    for (let j = i + 1; j < cells.length; j++) {
      const a = cells[i], b = cells[j];
      const ix = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
      const iy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
      if (ix > 1e-6 && iy > 1e-6) noOverlap = false;
    }
  }
  if (Math.abs((area / (w * h)) * 100 - 100) > 0.5) fill = false;
  const total = sizes.reduce((a, b) => a + b, 0);
  for (let i = 0; i < cells.length; i++) {
    const share = (cells[i].w * cells[i].h) / (w * h);
    const want = sizes[i] / total;
    // T1d-L07：判据从绝对百分点容差改为**相对误差判据**（带浮点地板）。
    // 绝对容差在微格上等于放行：面积归零（share=0）而目标占比极小的格子差远小于绝对容差
    // 照样过；相对判据下它的误差是 100%，必须红。现盘实测误差在浮点地板以下（现算：node tools/check-treemap-layout.mjs）。
    if (Math.abs(share - want) > Math.max(want * 0.01, 1e-6)) proportional = false;
  }
  return { inside, noOverlap, fill, proportional, worstAspect };
}
const sizes = [500, 300, 120, 80, 40, 20, 7, 3, 1, 1];
const items = sizes.map((v, i) => ({ size: v, path: `C:/x${i}` }));
const boxes = [[100, 46], [100, 10], [10, 200], [1000, 300], [3, 3]];

let allInside = true, allNoOverlap = true, allFill = true, allProportional = true, allCount = true;
let worstAspect = 0;
for (const [w, h] of boxes) {
  const cells = layout(items, w, h);
  if (cells.length !== items.length) allCount = false;
  const j = judgeCells(cells, w, h, sizes);
  if (!j.inside) allInside = false;
  if (!j.noOverlap) allNoOverlap = false;
  if (!j.fill) allFill = false;
  if (!j.proportional) allProportional = false;
  worstAspect = Math.max(worstAspect, j.worstAspect);
}

check(allCount, '项数守恒：每个非零体积项都拿到一个格子');
check(allInside, '格子不越出容器（越界会被 overflow 裁成"目录变小"）');
check(allNoOverlap, '格子互不重叠（重叠 = 点 A 跳到 B）');
check(allFill, '铺满容器：面积和 = 100%（±0.5%）');
check(allProportional, '面积占比 = 体积占比（相对误差 1%）');

// T1d-L07：渲染函数必须仍把布局函数当唯一真源。改名/内联一份私有布局后，上面几组
// 判据仍在测一个「已无人调用」的函数 —— 门禁绿而线上格子是另一套算法。
{
  const renderEnd = src.indexOf('\n  function ', end + 10);
  const renderBody = src.slice(end, renderEnd < 0 ? src.length : renderEnd);
  check(
    /\banTreemapLayout\s*\(/.test(renderBody),
    'renderAnTreemap 仍调用 anTreemapLayout（布局函数是唯一真源）',
    /\banTreemapLayout\s*\(/.test(renderBody) ? '' : '渲染函数体内找不到布局调用 —— 改名或内联了第二套实现',
  );
}

// T1d-L07：AN_TM_LOGIC_H（逻辑单位）⇄ .an-tm-box 高度（物理 px）的联动。
// 格子坐标以逻辑单位算，CSS 高度把它们线性放大；文字阈值（AN_TM_NAME_MIN_*）也按逻辑
// 单位比较，所以两者的比例 = 阈值在屏上的物理尺寸。2026-11-01 现算 230 / 46 = 5 px/单位；
// 改任一侧都必须重新核算「名字放不放得下」，这里钉住比例本身。
{
  const logicH = Number((src.match(/const AN_TM_LOGIC_H\s*=\s*(\d+)/) || [])[1]);
  const minNameH = Number((src.match(/const AN_TM_NAME_MIN_H\s*=\s*(\d+)/) || [])[1]);
  const subMinH = Number((src.match(/const AN_TM_SUB_MIN_H\s*=\s*(\d+)/) || [])[1]);
  const cssH = Number((readFileSync(PAGES_CSS, 'utf8').match(/\.an-tm-box\s*\{[^}]*\bheight:\s*(\d+)px/) || [])[1]);
  const PX_PER_LOGIC_UNIT = 5; // 230px / 46 逻辑单位（阈值物理尺寸的换算基准）
  check(
    logicH > 0 && cssH === logicH * PX_PER_LOGIC_UNIT,
    `CSS 高度 ⇄ JS 逻辑高联动（.an-tm-box ${cssH}px / AN_TM_LOGIC_H ${logicH} = ${PX_PER_LOGIC_UNIT}px/单位）`,
    logicH > 0 && cssH === logicH * PX_PER_LOGIC_UNIT ? '' : '两侧比例漂移：文字阈值的物理尺寸随之变化，格子会漏字或挤字',
  );
  check(
    minNameH > 0 && subMinH > minNameH && subMinH < logicH,
    `文字显隐阈值在逻辑高之内（名字 ${minNameH} / 副行 ${subMinH} < ${logicH}）`,
    minNameH > 0 && subMinH > minNameH && subMinH < logicH ? '' : '阈值越出容器或顺序颠倒 —— 名字/副行永远不会显示',
  );
}

// T1d-L03：性质判据必须能被合成违例打红（此前只喂真实 layout 结果）。
{
  const bad = judgeCells(
    [{ x: -1, y: 0, w: 60, h: 60 }, { x: 0, y: 0, w: 60, h: 60 }],
    100, 100, [1, 1],
  );
  const good = judgeCells(layout([{ size: 1, path: 'a' }, { size: 1, path: 'b' }], 100, 100), 100, 100, [1, 1]);
  check(
    !bad.inside && !bad.noOverlap && !bad.fill && good.inside && good.noOverlap,
    '正向对照：越界/重叠/漏铺的合成样本必判红，真实 layout 样本放行',
    `坏样本 inside=${bad.inside} overlap=${bad.noOverlap} fill=${bad.fill}`,
  );
  // T1d-L07：微格面积归零 —— 绝对百分点容差会放行，相对误差必须红。
  const zeroCell = judgeCells(
    [{ x: 0, y: 0, w: 50, h: 100 }, { x: 50, y: 0, w: 0, h: 100 }],
    100, 100, [1, 1],
  );
  check(
    !zeroCell.proportional && good.proportional,
    '正向对照：面积归零的微格必须判红（比例判据取相对误差），真实 layout 样本放行',
    `零面积样本 proportional=${zeroCell.proportional}`,
  );
}

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
