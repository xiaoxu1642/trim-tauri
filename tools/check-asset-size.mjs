// check-asset-size.mjs —— 前端产物体积门禁（审查 v3-F6）
//
// 为什么判红：src/ 里躺着 19MiB 级的 MiSans 字体，此前没有任何门禁拦「资源悄悄变大」——
// 打包体积回归（误拷大文件、字体被换成未子集化的全量版、壁纸换成原图）只能靠发版前人肉发现。
// 本门禁给三条护栏：
//   A. 单文件超过 PER_FILE_LIMIT 且未在 BASELINE 登记 → 红（新重资源必须显式登记）；
//   B. BASELINE 登记项超过登记 cap、或条目指向已不存在的文件 → 红（体积只许变小；
//      真要变大必须带着理由调 cap —— 与 check-guard-tiers 的双向棘轮同思路）；
//   C. src/ 全量超过 TOTAL_LIMIT → 红（总量兜底，防「每个文件都不大但攒了一堆」）。
//
// 用法：node tools/check-asset-size.mjs

import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const SRC = join(REPO_ROOT, 'src');
const PER_FILE_LIMIT = 1024 * 1024;   // 1 MiB：未登记单文件超限线（现第二大文件是 593KB 壁纸，留有距离）
const TOTAL_LIMIT = 24 * 1024 * 1024; // 24 MiB：当前实测 21.97 MiB，留 ~2MiB 迭代余量

/**
 * 已知重资源基线（登记 = 接受该体积；cap 为登记时的实测字节数）。
 * 新增条目必须写明「为什么大」。
 */
const BASELINE = {
  // 应用默认字体（--app-font-family 首选）：MiSans 可变字体，单文件覆盖全部字重，
  // 比拆多档静态字重更省；子集化会丢生僻字，中文清理文案不再安全，故按全量登记。
  'assets/fonts/MiSansVF.ttf': 20_093_424,
};

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const files = walk(SRC).map((p) => {
  const st = statSync(p);
  return { rel: relative(SRC, p).replace(/\\/g, '/'), size: st.size };
});

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

const fmt = (n) => (n / 1024 / 1024).toFixed(2) + ' MiB';

console.log('=== 前端产物体积门禁 ===\n');

// ---- A. 未登记的超大单文件 ----
const unlisted = files.filter((f) => f.size > PER_FILE_LIMIT && !(f.rel in BASELINE));
check(
  unlisted.length === 0,
  `A. 单文件 > ${fmt(PER_FILE_LIMIT)} 的资源均已登记（现登记 ${Object.keys(BASELINE).length} 项）`,
  unlisted.length
    ? `未登记超大文件 ${JSON.stringify(unlisted.map((f) => `${f.rel} ${fmt(f.size)}`))} —— 若确属必要，请连同理由登记进 BASELINE`
    : '',
);

// ---- B. 登记项棘轮（超 cap / 失踪条目）----
const missing = Object.keys(BASELINE).filter((rel) => !files.some((f) => f.rel === rel));
const grown = files.filter((f) => f.rel in BASELINE && f.size > BASELINE[f.rel]);
check(
  missing.length === 0 && grown.length === 0,
  `B. ${Object.keys(BASELINE).length} 项基线资源均未超登记体积`,
  [
    missing.length ? `条目指向的文件已不存在 ${JSON.stringify(missing)}（请从 BASELINE 移除）` : '',
    grown.length
      ? `超过登记体积 ${JSON.stringify(grown.map((f) => `${f.rel} ${fmt(f.size)} > cap ${fmt(BASELINE[f.rel])}`))}（确需变大请带理由调 cap）`
      : '',
  ]
    .filter(Boolean)
    .join('；'),
);

// ---- C. 全量兜底 ----
const total = files.reduce((s, f) => s + f.size, 0);
check(
  total <= TOTAL_LIMIT,
  `C. src/ 全量 ${fmt(total)} ≤ 上限 ${fmt(TOTAL_LIMIT)}（${files.length} 个文件）`,
  total > TOTAL_LIMIT
    ? '超过总量护栏：新增资源请先做子集化/压缩，或调整 TOTAL_LIMIT 并说明理由'
    : '',
);

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('体积门禁全部通过');
